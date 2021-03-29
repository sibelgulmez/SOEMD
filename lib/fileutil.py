import os

def getFilePaths(directory, extensionList=[], reverse=False):
    file_paths = []

    for root, directories, files in os.walk(directory):
        for filename in files:
            if (len(extensionList) > 0): 
                extension = os.path.splitext(filename)[1]

                if ((extension.lower() in extensionList) or (extension.upper() in extensionList)):
                    if (not reverse):
                        filepath = os.path.join(root, filename)
                        file_paths.append(filepath)
                elif (reverse):
                    filepath = os.path.join(root, filename)
                    file_paths.append(filepath)

            else:  
                filepath = os.path.join(root, filename)
                file_paths.append(filepath)

    print("Number of file found : " + str(len(file_paths)))
    return file_paths
