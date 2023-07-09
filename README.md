
# DFIniFileLibrary

DFiniFileLibrary Library for reading, writing, creating ini files with encryption/decryption of values in ini files.

To use the revised DFIniFileLibrary:

Create a new Delphi project or open an existing one.
Add the DFIniFileLibrary unit to your project.
To write an encrypted string value to an .ini file, call the WriteEncryptedString function and provide the file name, section, key, value, and password as parameters. For example:

TDFIniFileLibrary.WriteEncryptedString('C:\mysettings.ini', 'Section1', 'Key1', 'SensitiveData', 'MyPassword');



To read an encrypted string value from an .ini file, call the ReadEncryptedString function and provide the file name, section, key, default value, and password as parameters. The function will decrypt the value from the .ini file using the provided password, or return the default value if the key doesn't exist. For example:

var
  
  Value: string;

begin

  Value := TDFIniFileLibrary.ReadEncryptedString('C:\mysettings.ini', 'Section1', 'Key1', 'Default', 'MyPassword');

  ShowMessage(Value);
  
end;
