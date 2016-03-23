SNIFF: A Python exercise in content sniffing
--------------------------------------------

SNIFF will attempt to distinguish between Binary, HTML, JavaScript, and Plain Text files.

## Installation

This library relies only on built-in Python objects. It has been tested on Python 2.7 and 3.5 on
Mac OS X 10.11.

To get the code you may download a [ZIP file](https://github.com/ahankinson/sniff/archive/master.zip)
of the latest version, or clone the repository:

    $> git clone https://github.com/ahankinson/sniff.git

## Running

The program can be run on the command line:

    $> python sniff.py path/to/file.html

Alternatively, it may be executable directly on your machine:

    $> ./sniff.py path/to/file.js

## Testing

A test script and test files are included in the download:

    $> python testrunner.py

It will run the filetype sniffer over three test sets containing a number of HTML, JavaScript,
and plaintext files, and produce an overall score for its predictions on these files. The test set is drawn from a number of places, including test sets for HTML, JavaScript, and Plain Text encodings. Consult the README in each subforlder in test for the sources of each set of files.

## Design

The content sniffer is implemented using a two-point-five-pass detection to form hypotheses about the
nature of the content. It does not look at the filename extension. An empty file is treated as a plain
text file.

As a preprocessing step ("point five"), the system will look for the occurrence of any `<script>` tags and strip
out their contents; this will reduce the number of false positive Javascript results.

The first pass sorts and enumerates the byte distribution in the file; if it contains a greater proportion of angle brackets, `<` and `>`,
this will result in a first hypothesis of HTML; similarly, a greater proportion of curly brackets, `{` and `}`,
and parentheses, `(` and `)`, will result in a hypothesis of Javascript. These numbers are normalized over
all bytes present in the file, giving an overall percentage of the HTMLiness or Javascriptiness of the file.

The second pass uses a heuristic to examine the contents of the file. It will look for `<!DOCTYPE`
and `<!html` and posit that it is HTML; It will then look at the file for any occurrences of `var ` and
`function` and add those occurrences to the Javascript hypothesis.

If it finds neither of these indicators it will set a high prediction for text, allowing the system to fall
back to a Plain Text result.

## Results

The current version achieves the following results with the included test set.

    Correct Binary Identification: 2/2 = 100.00%
    Correct HTML Identification: 53/53 = 100.00%
    Correct JS Identification: 98/98 = 100.00%
    Correct Text Identification: 16/26 = 61.54%

Included in the test set are a number of files that attempt to address some corner cases:

1. In the JS files there are examples containing JSX formatted code. This format mixes in angle
brackets with the standard JS code, so it is included to try and fool the first pass results. However,
since the second pass is implicitly weighted more than the first pass, the presence of `var ` and `function `, as
well as the absence of a DOCTYPE indicator in these files weights it towards a javascript file.

2. In the HTML files there is one file, 1_3_BF-01.htm, with some javascript in the text. This passes as HTML,
however, since the percentage of byte frequency of the angle brackets, in addition to it featuring
a DOCTYPE declaration, weights it towards being an HTML file.

3. Where the system fails is detecting between most files and plain text. Since there are few
distinguishing features of all plain text files, it will default to this prediction. However,
it will fail if the plain text file is encoded in UTF16 since it sees the BOM and assumes the
file is binary. It will also fail to predict a plain text with a file that has a lot of HTML tags.

4. XML is treated as plain text for the purposes of this exercise. XML would throw off the first pass, but the second pass does not predict HTML since it does not contain the appropriate doctype declaration. The test set contains two types of XML, one encoding using MusicXML ('.xml') and three encoded using the Music Encoding Initiative (".mei")

## Limitations

While Byte Frequency Analysis is an accepted form of file type identification, this particular implementation is tuned to the specific task of distinguishing JavaScript, HTML, and Plain Text, and is not useful for any other file types.
