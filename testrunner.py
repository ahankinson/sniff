import os
from sniff import ContentTypeSniffer

# Treat files with these extensions as one of four types:
binary = ['.pyc', '.DS_Store']
html = ['.html', '.htm']
js = ['.js']
text = ['.txt', '.py', '.mei', '.xml']

if __name__ == "__main__":
    total_html = 0
    total_js = 0
    total_text = 0
    total_bin = 0

    correct_html = 0
    correct_js = 0
    correct_text = 0
    correct_bin = 0

    for dir, subdirs, files in os.walk('test'):
        for f in files:
            fname, ext = os.path.splitext(f)

            # Corner case for dealing with .DS_Store files.
            if not ext:
                extension = fname
            else:
                extension = ext

            if extension in binary:
                filetype = 'binary'
                total_bin += 1
            elif extension in html:
                filetype = 'HTML'
                total_html += 1
            elif extension in js:
                filetype = 'Javascript'
                total_js += 1
            else:
                filetype = 'Plain Text'
                total_text += 1

            c = ContentTypeSniffer(os.path.join(dir, f), debug=True)
            classification = c.sniff()
            print("{0} ({1}) is {2}".format(f, filetype, classification))

            print("HTML Hypothesis: {0}".format(c.hypothesis_html))
            print("JS Hypothesis: {0}".format(c.hypothesis_javascript))
            print("Text Hypothesis: {0}".format(c.hypothesis_text))

            if filetype == classification:
                print("Correctly identified")
                if filetype == 'binary':
                    correct_bin += 1
                elif filetype == 'HTML':
                    correct_html += 1
                elif filetype == 'Javascript':
                    correct_js += 1
                else:
                    correct_text += 1
            else:
                print("^^^^^^^^^^^^^^ INCORRECT ^^^^^^^^^^^^^^^^^")
            print("----------------------------------------------------")

    print("Correct Binary Identification: {0}/{1} = {2:.2f}%".format(correct_bin, total_bin, ((float(correct_bin)/total_bin) * 100)))
    print("Correct HTML Identification: {0}/{1} = {2:.2f}%".format(correct_html, total_html, ((float(correct_html)/total_html) * 100)))
    print("Correct JS Identification: {0}/{1} = {2:.2f}%".format(correct_js, total_js, ((float(correct_js)/total_js) * 100)))
    print("Correct Text Identification: {0}/{1} = {2:.2f}%".format(correct_text, total_text, ((float(correct_text)/total_text) * 100)))
