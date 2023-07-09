unit DFIniFileLibrary;

interface

type
  TDFIniFileLibrary = class
    class procedure WriteEncryptedString(const FileName, Section, Key, Value: string; const Password: string);
    class function ReadEncryptedString(const FileName, Section, Key, DefaultValue: string; const Password: string): string;
    class procedure CreateIniFile(const FileName: string);
  end;

implementation

uses
  System.IniFiles, System.SysUtils, System.Classes, System.Hash, System.IOUtils;

class procedure TDFIniFileLibrary.WriteEncryptedString(const FileName, Section, Key, Value: string; const Password: string);
var
  IniFile: TIniFile;
  EncryptedValue: string;
begin
  EncryptedValue := EncryptValue(Value, Password);
  IniFile := TIniFile.Create(FileName);
  try
    IniFile.WriteString(Section, Key, EncryptedValue);
  finally
    IniFile.Free;
  end;
end;

class function TDFIniFileLibrary.ReadEncryptedString(const FileName, Section, Key, DefaultValue: string; const Password: string): string;
var
  IniFile: TIniFile;
  EncryptedValue: string;
begin
  IniFile := TIniFile.Create(FileName);
  try
    EncryptedValue := IniFile.ReadString(Section, Key, '');
    if EncryptedValue <> '' then
      Result := DecryptValue(EncryptedValue, Password)
    else
      Result := DefaultValue;
  finally
    IniFile.Free;
  end;
end;

class procedure TDFIniFileLibrary.CreateIniFile(const FileName: string);
var
  IniFile: TIniFile;
begin
  if not FileExists(FileName) then
  begin
    IniFile := TIniFile.Create(FileName);
    try
      // Do nothing; simply create an empty .ini file
    finally
      IniFile.Free;
    end;
  end;
end;

class function TDFIniFileLibrary.EncryptValue(const Value, Password: string): string;
var
  HashBytes, ValueBytes: TBytes;
begin
  ValueBytes := TEncoding.UTF8.GetBytes(Value);
  HashBytes := THashSHA2.GetHashBytes(TEncoding.UTF8.GetBytes(Password));
  for var I := 0 to Length(ValueBytes) - 1 do
    ValueBytes[I] := ValueBytes[I] xor HashBytes[I mod Length(HashBytes)];
  Result := TNetEncoding.Base64.EncodeBytesToString(ValueBytes);
end;

class function TDFIniFileLibrary.DecryptValue(const EncryptedValue, Password: string): string;
var
  HashBytes, ValueBytes: TBytes;
begin
  ValueBytes := TNetEncoding.Base64.DecodeStringToBytes(EncryptedValue);
  HashBytes := THashSHA2.GetHashBytes(TEncoding.UTF8.GetBytes(Password));
  for var I := 0 to Length(ValueBytes) - 1 do
    ValueBytes[I] := ValueBytes[I] xor HashBytes[I mod Length(HashBytes)];
  Result := TEncoding.UTF8.GetString(ValueBytes);
end;

end.
