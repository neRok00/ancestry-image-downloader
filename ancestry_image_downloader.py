"""

Copyright (c) 2016 neRok00 https://github.com/neRok00

Permission to use, copy, modify, and/or distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright notice
and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE.

"""

################################################################################
# Enter your details between the quotation marks ("), then run the script.
# For instructions and further details, visit
# http://neRok00.github.io/ancestry-image-downloader
# Note, usage of this script is prohibited in the Ancestry Terms and Conditions.
# USAGE OF THIS SCRIPT IS AT YOUR OWN RISK, AND YOU ACCEPT ALL LIABILTY IN DOING SO!
#
# Version 1.5, released 03 Feb 2018.
################################################################################

USERNAME = ""
PASSWORD = ""
GEDCOM_FILE = r""
OUTPUT_DIRECTORY = r""

"""
Have you read the warnings and understand that YOU will be violating
YOUR AGREEMENT with the Ancestry Terms and Conditions by using this script,
and that you accept all responsibilty and liability in doing so?
"""

DO_YOU_ACCEPT = "No"

################################################################################
# Do not change anything below this line.
################################################################################

import re
import requests
import csv
import os
import logging
import mimetypes
from collections import defaultdict

class GedcomFileInvalid(Exception):
    pass

class LoginError(Exception):
    pass

class FileExistsError(Exception):
    pass

def validate_gedcom_file(file_path, encoding="utf8"):
    """
    Takes a file path to a gedcom file, and validates that file.

    Returns the file text.
    """

    # Check we have a file path.
    if not file_path:
        raise GedcomFileInvalid('No file path entered.')

    # Check file exists.
    if not os.path.exists(file_path):
        raise GedcomFileInvalid('A file cannot be found at the provided path.')

    # Read the file contents.
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            file_text = f.read()
    except Exception as e:
        raise GedcomFileInvalid('There was an error when reading the file: ' + str(e))

    # Check we have a gedcom head section.
    file_head = re.search('^([ \t]*0 HEAD\s+(?:^[ \t]*(?!0)\d+ [A-Z_]+(?: .*)?\s+)*)', file_text, re.MULTILINE)
    if not file_head:
        raise GedcomFileInvalid('The file cannot be verified as a gedcom file, as it does not have a header section.')
    else:
        file_head = file_head.group(0)

    # Check the gedcom source is ancestry.
    file_head_sour = re.search('^[ \t]*1 SOUR (.*)$', file_head, re.MULTILINE)
    if not file_head_sour:
        raise GedcomFileInvalid('The header of this gedcom file does not provide a source, so the file cannot be verirified from Ancestry.com.')
    elif file_head_sour.group(1) != 'Ancestry.com Family Trees':
        raise GedcomFileInvalid('The header of this gedcom file indicates its source is not Ancestry.com, but {0}.'.format(file_head_sour.group(1)))

    return file_text

def process_gedcom_text(text):
    """
    Extract all the app id's from the gedcom text.

    Returns a tuple of ID's of the form (Source, APID, Indiv, DB, Record/Person)
    """

    regex = re.compile(
        r'^[ \t]*\d+ SOUR (@?[\D]*\d+@?)\s+(?:^[ \t]*\d+ (?!SOUR)[A-Z_]+(?: .*)?\s+)*^[ \t]*\d+ _APID ((\d+),(\d+)::(\d+))',
        re.MULTILINE
    )

    matches = regex.findall(text)

    return matches

def start_session(username, password):
    """
    Starts a session against the specified Ancestry website. Checks login was succesful.

    Returns the session.
    """

    session = requests.Session()

    payload = {
        'action': 'https://www.ancestry.com/secure/login',
        'username': username,
        'password': password,
    }

    response = session.post(payload['action'], data=payload)

    if ( response.status_code == 200 and
         not response.url.startswith("https://www.ancestry.com/secure/Login") and
         'USERID' in response.cookies['VARS']
    ):
        return session
    else:
        raise LoginError()

def setup_output(path, file_name='output'):
    """
    Takes a file path, and optional file name parameter.

    Checks the folder exists, and the file does not.

    Returns a tuple of (csv file handle, csv writer, logger).
    """

    # Check the output directory exists.
    if not os.path.exists(path):
        os.makedirs(path)

    # Move into the output directory for relative file locations.
    os.chdir(path)

    # Check the CSV file doesn't already exist.
    csv_file_name = file_name + '.csv'
    if os.path.exists(csv_file_name):
        raise FileExistsError(os.path.abspath(csv_file_name))

    # Create CSV file.
    csv_file = open(csv_file_name, 'w', newline='')
    csv_writer = csv.DictWriter(csv_file, fieldnames=('apid', 'indiv', 'dbid', 'pid', 'sour', 'image', 'extension'))
    csv_writer.writeheader()

    # Check the log file doesn't already exist.
    log_file_name = file_name + '.log'
    if os.path.exists(log_file_name):
        raise FileExistsError(os.path.abspath(log_file_name))

    # Create the logger.
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    file_log_handler = logging.FileHandler(log_file_name)
    logger.addHandler(file_log_handler)

    stderr_log_handler = logging.StreamHandler()
    logger.addHandler(stderr_log_handler)

    return (csv_file, csv_writer, logger)

def process_apids(apid_matches, *, session, csv_writer, logger):
    """
    Given a list of APID tuples as returned by `process_gedcom_text()`,
    an active session, and a csv writer, it downloads images from Ancestry.com.

    Presumes the current directory of `os` is the output directory.

    Returns a list of apids with errors.
    """

    total_apid_matches = len(apid_matches)
    processed_apids = defaultdict(list) # A dict with dbids as keys, and items as a list of pids.
    iid_regex = re.compile(r"var iid='([^\s']+)';")
    processed_iids = {} # A dict with IID's as keys, and the following object as items.

    class processed_iid(object):
        def __init__(self, extension, apids=[]):
            self.extension = extension
            self.apids = apids

    problem_apids = set()

    # Process each apid.
    for i, match in enumerate(apid_matches, start=1):

        sour, apid, indiv, dbid, pid = match

        fields = {
            'sour': sour,
            'apid': apid,
            'indiv': indiv,
            'dbid': dbid,
            'pid': pid,
        }

        logger.info("Processing APID {0} of {1} <APID {2}>...".format(i, total_apid_matches, apid))

        # Check if the apid has previously been processed.
        if dbid in processed_apids and pid in processed_apids[dbid]:
            logger.info("    > APID previously processed as part of another source.")
            logger.info("    > Finished!")
            continue
        else:
            # Mark the apid as processed now, so even if something fails, we know not to check it again.
            processed_apids[dbid].append(pid)

        # Visit the record page corresponding to the app id.
        logger.info("    > Getting the record page for the APID...")
        record_page = session.get('http://search.ancestry.com/cgi-bin/sse.dll?indiv={0}&dbid={1}&h={2}'.format(indiv, dbid, pid))
        if record_page.status_code != 200:
            logger.error("    > There was an error when trying to get the record page for the APID.")
            problem_apids.add(apid)
            logger.info("    > Aborted!")
            continue

        # Extract the image id associated with the record from the returned html.
        logger.info("    > Processing the record page to determine the image ID...")
        match = iid_regex.search(record_page.text)

        if not match:
            # TODO, more and better checks could be performed rather than presuming there is no image at this stage, such as checking for a thumbnail.
            logger.info("    > An image ID could not be found. Either the record does not have an image, or the record page was in an unexpected format.")
            fields['image'] = ''
            fields['extension'] = ''
            logger.info("    > Writing results to CSV file...")
            csv_writer.writerow(fields)
            logger.info("    > Finished!")
            continue

        fields['image'] = iid = match.group(1)

        # Check if the iid has previously been processed.
        if iid in processed_iids:
            logger.info("    > The image for this record has previously been processed.")
            fields['extension'] = processed_iids[iid].extension
            logger.info("    > Writing results to CSV file...")
            csv_writer.writerow(fields)
            processed_iids[iid].apids.append(apid)
            logger.info("    > Finished!")
            continue
        else:
            # Mark the iid as processed now, so even if something fails, we know not to check it again.
            processed_iids[iid] = processed_iid(None, [apid])

        # Get the api data related to the image.
        logger.info("    > Get information regarding the image...")
        image_page = session.get('http://interactive.ancestry.com/api/v2/Media/GetMediaInfo/{0}/{1}/{2}'.format(dbid, iid, pid))
        if record_page.status_code != 200:
            logger.error("    > There was an error when trying to get the image info.")
            problem_apids.add(apid)
            logger.info("    > Aborted!")
            continue

        # Extract the download url for the returned json.
        logger.info("    > Processing the image information...")
        image_page_json = image_page.json()
        try:
            download_url = image_page_json['ImageServiceUrlForDownload']
        except KeyError:
            logger.error("    > There was an error when trying to get the download URL from the image info.")
            problem_apids.add(apid)
            logger.info("    > Aborted!")
            continue

        # Download the image.
        logger.info("    > Downloading image...")
        image_download = session.get(download_url, stream=True)

        if image_download.status_code != 200:
            logger.error("    > There was an error when trying to download the image.")
            problem_apids.add(apid)
            logger.info("    > Aborted!")
            continue

        # Save the image to a file.
        logger.info("    > Saving image...")

        # Ensure the dbid has a folder for saving the image into.
        if not os.path.exists(dbid):
            os.makedirs(dbid)

        content_type = image_download.headers['content-type']
        extension = mimetypes.guess_extension(content_type).strip('.')
        if extension == 'jpeg' or extension == 'jpe':
            extension = 'jpg'
        fields['extension'] = extension
        # Ensure the extension has been recorded for later use.
        if processed_iids[iid].extension == None: processed_iids[iid].extension = extension

        try:
            with open("{0}/{1}.{2}".format(dbid, iid, extension), 'wb') as f:
                for chunk in image_download.iter_content(1024):
                    f.write(chunk)
        except Exception as e:
            logger.error('    > There was an unknown error when saving the file: ' + str(e))
            logger.info("    > Aborted!")
            continue

        logger.info("    > Image file saved successfully.")

        # Write results to csv file.
        logger.info("    > Writing results to CSV file...")
        csv_writer.writerow(fields)
        logger.info("    > Finished!")

    # All done.
    return problem_apids

def run(*, gedcom, username, password, output_directory, output_filename=None):

    # Validate the gedcom file.
    print("Validating gedcom file...")
    try:
        file_text = validate_gedcom_file(gedcom)
    except GedcomFileInvalid as e:
        print("The following problem was encountered when validating the file;")
        print(e)
        print("Aborting.")
        return
    else:
        print("Gedcom file appears valid.")

    # Process the gedcom file text.
    print("Processing gedcom file (may take a few minutes)...")
    apid_matches = process_gedcom_text(file_text)

    if len(apid_matches) == 0: # No apids to scrape images for.
        print("Gedcom file processed, no matches found.")
        print("Finished.")
        return
    else:
        print("Gedcom file processed, {0} matches found.".format(len(apid_matches)))

    question = "\nReady to start downloading images.\n\n"\
            "!!! Accessing Ancestry websites using an 'automatic access tool'\n"\
            "!!! is PROHIBITED by the Ancestry Terms and Conditions.\n"\
            "!!! This script is an 'automatic access tool'! \n"\
            "!!! If you proceed past this point, your could be found in violiation of the T&C's.\n"\
            "!!! More information is available on the website you downloaded this script from.\n"\
            "!!! \n"\
            "!!! Do you wish to continue at your own risk, and agree that you accept all liabilty in doing so?\n"\
            "!!! (Type 'Agree' to continue, or anything else to cancel/stop/disagree).\n"
    if not input(question).lower() == 'agree':
        print("Because you do not agree, the script will not proceed.")
        print("Aborting.")
        return

    print("Attempting to login to Ancestry.com...")
    try:
        session = start_session(username, password)
    except LoginError:
        print("There was a problem when logging into Ancestry.com. Perhaps check your details and try again.")
        print("Aborting.")
        return
    else:
        print("Login successful.")

    print("Creating output folder and files...")
    if output_filename == None:
        output_filename = os.path.basename(gedcom).split('.')[0]
    try:
        csv_file, csv_writer, logger = setup_output(output_directory, file_name=output_filename)
    except FileExistsError as e:
        print("The following output file cannot be created because it already exists: {0}".format(e))
        print("Aborting.")
        return
    else:
        print("Output files and folders created.")

    print("Begin processing the APID's and images...")

    try:
        problem_apids = process_apids(apid_matches, session=session, csv_writer=csv_writer, logger=logger)
    except KeyboardInterrupt:
        print("Processing of APIDs interrupted.")
    else:
        print("All APID's processed. There were errors with {0} APIDs.".format(len(problem_apids)))

    print("Closing files...")
    csv_file.close()
    for handler in logger.handlers: handler.close()
    print("Finished!")

if __name__ == '__main__':

    if DO_YOU_ACCEPT.lower() != 'yes':
        print("As you have not consented/agreed to the warning statement at the top of this script, it will now close.")
    else:
        run(gedcom=GEDCOM_FILE, username=USERNAME, password=PASSWORD, output_directory=OUTPUT_DIRECTORY)

        print("\nPlease support this script creators efforts by donating via Paypal at the following link;")
        print("http://http://neRok00.github.io/ancestry-image-downloader")
        import time
        time.sleep(5)
