#get all the file name in templates folder and content and print out one by one
import os

def get_file_templates():
    file_name = []
    for root, dirs, files in os.walk('templates'):
        for file in files:
            if file.endswith('.html'):
                file_name.append(file)
    for file in file_name:
        print("File name: " + file)
        file = os.path.join('templates', file)
        with open(file, 'r') as f:
            print(f.read())
        print('done')


#get all the python file with name and content print out one by one, from current folder
def get_file_content():
    file_name = []
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file.endswith('.py'):
                file_name.append(file)
    for file in file_name:
        print("File name: " + file)
        with open(file, 'r') as f:
            print(f.read())
        print('done')
get_file_templates()
get_file_content()