#! /usr/bin/env python

import re
from collections import Counter
import sys

sysversion = sys.version_info[0]

# Constants for the ASCII character code. There is a difference between the behaviour
#  of the Counter object between Python 2 and 3; Python 3 will sort it in to byte buckets,
#  while Python 2 will sort it into Character buckets.
LESS_THAN = 60 if sysversion > 2 else "<"
GREATER_THAN = 62 if sysversion > 2 else ">"
LEFT_CURLY = 123 if sysversion > 2 else "{"
RIGHT_CURLY = 125 if sysversion > 2 else "}"
LEFT_PAREN = 40 if sysversion > 2 else "("
RIGHT_PAREN = 41 if sysversion > 2 else ")"

# The threshold for plaintext
PLAINTEXT_THRESH = 1


class ContentTypeSniffer:
    """
        Based on a simplified Byte Frequency Analysis approach.
        Namely, we expect that a JavaScript file will have more parentheses and curly brackets,
        while an HTML file will have more angle brackets.

        The sniffing code doesn't actually look at the filename extension; That, of course,
        is probably something that should be factored in to a live sniffing system, but
        the purpose of this method is to demonstrate its effectiveness in determining mislabelled
        file types.
    """

    def __init__(self, filename, debug=False):
        f = open(filename, 'rb')
        self.file_bytes = f.read()
        f.close()

        self.total_bytes = len(self.file_bytes)
        self.byte_bins = None
        self.hypothesis_html = 0
        self.hypothesis_javascript = 0
        self.hypothesis_text = 0

    def sniff(self):
        if self._check_is_binary():
            return "binary"

        # Report that an empty file is a plain text file.
        if self.total_bytes == 0:
            return "Plain Text"

        self._preprocess_file()
        self._enumerate_byte_bins()
        self._first_pass()
        self._second_pass()

        if self.hypothesis_html >= (self.hypothesis_javascript + self.hypothesis_text):
            return 'HTML'
        elif self.hypothesis_javascript > (self.hypothesis_html + self.hypothesis_text):
            return 'Javascript'
        else:
            return 'Plain Text'

    def _check_is_binary(self):
        """
        Checks whether a file is binary or not by looking for a null byte.
        Will report incorrectly on UTF16 files.
        Adapted from http://eli.thegreenplace.net/2011/10/19/perls-guess-if-file-is-text-or-binary-implemented-in-python/
        :return: Boolean
        """
        if b'\x00' in self.file_bytes:
            return True
        return False

    def _preprocess_file(self):
        # if present, find and remove the contents of any <script> tags;
        # this will help reduce false positives.
        re.sub(b'<script>(.*)</script>', b'<script></script>', self.file_bytes)

    def _enumerate_byte_bins(self):
        """
            For each character in the file, count their occurrences and
            store a running total of the number.

            Uses the built-in Counter object from the collections module
        """
        self.byte_bins = Counter(self.file_bytes)

    def _first_pass(self):
        """
            Compares the number of angle brackets (<>) with the number of parens and curly brackets ({}).
            A greater proportion of angle brackets increases the likelihood that it will
            be an HTML file.
        """
        num_angles = self.byte_bins[LESS_THAN] + self.byte_bins[GREATER_THAN]
        num_curly_paren = self.byte_bins[LEFT_CURLY] + self.byte_bins[RIGHT_CURLY] + \
                    self.byte_bins[LEFT_PAREN] + self.byte_bins[RIGHT_PAREN]

        percent_html = float(num_angles) / self.total_bytes
        percent_js = float(num_curly_paren) / self.total_bytes

        if percent_html >= percent_js:
            self.hypothesis_html += percent_html
        else:
            # Increase the competing javascript hypothesis
            self.hypothesis_javascript += percent_js

    def _second_pass(self):
        """
            Checks for the presence of highly likely byte sequences, like <!html or <!DOCTYPE
             for HTML; 'function' or 'var ' for JS.
        """
        html_matches = re.findall(b'<!html|<!DOCTYPE html', self.file_bytes, re.IGNORECASE)
        if html_matches:
            self.hypothesis_html += 1

        js_matches = re.findall(b'var\s+|function', self.file_bytes)
        if js_matches:
            self.hypothesis_javascript += 1

        # If the file contains neither the doctype nor a significant amount of var/function,
        # significantly increase the likelihood that it's a plain text file.
        if not html_matches and not js_matches:
            self.hypothesis_text += PLAINTEXT_THRESH


def main(filename):
    c = ContentTypeSniffer(filename)
    print("Content type: {0}".format(c.sniff()))

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="A file content sniffer.")
    parser.add_argument('file', help="Path to the file you wish to sniff.")
    args = parser.parse_args()
    main(args.file)
