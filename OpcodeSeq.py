import os
import output
import fileutil
import OpCode


def opcode_process(process_function, output_ext, delimeter=',', dataset='dataset', extensionList=['.exe', '.dll'],feature_type="text"):

    if os.path.isfile(dataset):
        # Get content
        content = process_function(dataset, delimeter=delimeter)
        if content is not None:
            try:
                if feature_type == "seq":
                    output.writeFeatureAsSequence(dataset, output_ext, content)
                else:
                    output.writeIntoFile(dataset, output_ext, content)
            except IOError as ioe:
                print(str(ioe))
            print("core process for file "+dataset+" completed")
        else:
            print("file "+dataset+" is empty")
    elif os.path.isdir(dataset):
        listOfFile = fileutil.getFilePaths(dataset, extensionList)

        for index, filename in enumerate(listOfFile):
            # Get content
            content = process_function(filename, delimeter=delimeter)
            if content is not None:
                try:
                    if feature_type == "seq":
                        output.writeFeatureAsSequence(filename, output_ext, content)
                    else:
                        output.writeIntoFile(filename, output_ext, content)
                except IOError as ioe:
                    print(str(ioe))
            print("opcode process: " + str(index) + "  -  " + str(len(listOfFile)))
    else:
        print('File type must be file or directory.')



if __name__ == "__main__":
    dataset =""
    extensionList = [".exe", ".dll", ".com"]
    opcode_process(OpCode.getOpcode, 'opcode', ',', dataset, extensionList, "text")
