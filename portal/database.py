import copy


class User:

    def __init__(self, username, password, roles):
        self.username = username
        self.password = password
        self.roles = copy.deepcopy(roles)


class Administrator(User):
    def __init__(self, username, password):
        super().__init__(username, password, ['admin'])


class Database:
    RESULT_SUCCESS = 1

    def __init__(self):
        self.username_password = {}
        self.username_roles = {}
        self.role_permissions = {}

    def add_user(self, user):
        if user.username in self.username_password:
            return 0
        else:
            self.username_password[user.username] = user.password
            self.username_roles[user.username] = copy.deepcopy(user.roles)
            return 1

    def add_role(self, role_name, permissions):
        if role_name in self.role_permissions:
            return 0
        else:
            self.role_permissions[role_name] = copy.deepcopy(permissions)
            return 1

    def remove_user(self, username):
        if username in self.username_password and username in self.username_roles:
            del self.username_password[username]
            del self.username_roles[username]
            return 1
        else:
            return 0

    def remove_role(self, role_name):
        if role_name in self.role_permissions:
            del self.role_permissions[role_name]
            return 1
        else:
            return 0

    def authenticate_user(self, username, password):
        return username in self.username_password and self.username_password[username] == password

    def verify_permission(self, user, permission):
        for role in self.username_roles[user.username]:
            for perm in self.role_permissions[role]:
                if perm == permission:
                    return True
        return False
