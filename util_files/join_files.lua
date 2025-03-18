local lfs = require("lfs")

local function toHex(str)
    return (str:gsub(".", function(c)
        return string.format("%02x", string.byte(c))
    end))
end

local function writeFileWithMetadata(outputFile, filePath, content)
    local hexContent = toHex(content)

    outputFile:write("###FILE_START###\n")
    outputFile:write("FILE_PATH: " .. filePath .. "\n")
    outputFile:write("###CONTENT_START###\n")
    outputFile:write(hexContent)
    outputFile:write("\n###CONTENT_END###\n")
end

local function joinFilesRecursively(folderPath, outputFile)
    folderPath = folderPath:gsub("[\\/]+$", "")

    for file in lfs.dir(folderPath) do
        if file ~= "." and file ~= ".." then
            local filePath = folderPath .. "/" .. file
            local attributes = lfs.attributes(filePath)

            if attributes and attributes.mode == "file" then
                local inputFile = io.open(filePath, "rb")
                if inputFile then
                    local content = inputFile:read("*all")
                    inputFile:close()

                    writeFileWithMetadata(outputFile, filePath, content)
                else
                    print("Error opening file: " .. filePath)
                end

            elseif attributes and attributes.mode == "directory" then
                joinFilesRecursively(filePath, outputFile)
            end
        end
    end
end

local folderToJoin = arg[1]
local outputFilePath = arg[2]

if not folderToJoin or not outputFilePath then
    print("Usage: lua script.lua <folder_path> <output_file>")
    os.exit(1)
end

local outputFile = io.open(outputFilePath, "w")
if outputFile then
    joinFilesRecursively(folderToJoin, outputFile)
    outputFile:close()
    print("Files joined into " .. outputFilePath)
else
    print("Failed to open output file.")
end