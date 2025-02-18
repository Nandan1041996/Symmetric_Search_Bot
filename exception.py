
# dicti = {'Q_A_sheet_IT_security_policy.xlsx': '1qGj6W4PqEkvOrXkrJWfdwmqeuMv2RSC5'}

# for file,id in dicti.items():
#     print(file,id)

class FileNotAvailable(Exception):
    'File Not Available.'
    def __init__(self):
        self.msg = 'File Not Available in google drive.'
    def __str__(self):
        return self.msg
    
class TableNotExist(Exception):
    'Table Not Found.'
    def __init__(self):
        self.msg = 'Table Not Found.Please Check In Database.'
    def __str__(self):
        return self.msg

class FolderNotAvailable(Exception):
    'Folder Not Available.'
    def __init__(self):
        self.msg = 'In Google Drive Folder Not Available.'
    def __str__(self):
        return self.msg

    
class EmailExist(Exception):
    'Email already exist.'
    def __init__(self):
        self.msg = 'Email already exist.'
    def __str__(self):
        return self.msg
    
class PgConnectionError(Exception):
    'PostgreSQL Connection Failed.'
    def __init__(self):
        self.msg = 'PostgreSQL Connection Failed.'
    def __str__(self):
        return self.msg





