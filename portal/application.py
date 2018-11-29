import database as db
import tkinter as tk
import webbrowser


class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)

        self.database = db.Database()
        self.current_user = None
        self.newlinks = []
        self.urls = {}

        # Control Variables
        self.ctrl_username = tk.StringVar()
        self.ctrl_password = tk.StringVar()
        self.ctrl_role_name = tk.StringVar()
        self.ctrl_link1 = tk.StringVar()
        self.ctrl_link2 = tk.StringVar()
        self.ctrl_link3 = tk.StringVar()
        self.ctrl_check1 = tk.IntVar()
        self.ctrl_check2 = tk.IntVar()
        self.ctrl_check3 = tk.IntVar()
        self.ctrl_check4 = tk.IntVar()
        self.ctrl_check5 = tk.IntVar()
        self.ctrl_check6 = tk.IntVar()
        self.ctrl_checks = [self.ctrl_check1,
                            self.ctrl_check2,
                            self.ctrl_check3,
                            self.ctrl_check4,
                            self.ctrl_check5,
                            self.ctrl_check6]

        # Frames
        self.frame1 = tk.Frame(self)  # login
        self.frame2 = tk.Frame(self)  # home
        self.frame3 = tk.Frame(self)  # add user
        self.frame4 = tk.Frame(self)  # remove user
        self.frame5 = tk.Frame(self)  # add role
        self.frame6 = tk.Frame(self)  # remove role
        self.frame7 = tk.Frame(self.frame3)  # role check buttons
        self.frame8 = tk.Frame(self.frame2)  # links

        # Widgets
        self.check_button1 = tk.Checkbutton(self.frame7, variable=self.ctrl_check1)
        self.check_button2 = tk.Checkbutton(self.frame7, variable=self.ctrl_check2)
        self.check_button3 = tk.Checkbutton(self.frame7, variable=self.ctrl_check3)
        self.check_button4 = tk.Checkbutton(self.frame7, variable=self.ctrl_check4)
        self.check_button5 = tk.Checkbutton(self.frame7, variable=self.ctrl_check5)
        self.check_button6 = tk.Checkbutton(self.frame7, variable=self.ctrl_check6)
        self.check_buttons = [self.check_button1,
                              self.check_button2,
                              self.check_button3,
                              self.check_button4,
                              self.check_button5,
                              self.check_button6]

        self.label_frame1_username = tk.Label(self.frame1, text='Username')
        self.label_frame1_password = tk.Label(self.frame1, text='Password')
        self.label_frame1_error = tk.Label(self.frame1, text='Invalid user info')
        self.label_frame3_username = tk.Label(self.frame3, text='Username')
        self.label_frame3_password = tk.Label(self.frame3, text='Password')
        self.label_frame3_error = tk.Label(self.frame3, text='User already exists')
        self.label_frame4_username = tk.Label(self.frame4, text='Username')
        self.label_frame4_error = tk.Label(self.frame4, text='User does not exist')
        self.label_frame5_role_name = tk.Label(self.frame5, text='Role')
        self.label_permission1 = tk.Label(self.frame5, text='Permission 1')
        self.label_permission2 = tk.Label(self.frame5, text='Permission 2')
        self.label_permission3 = tk.Label(self.frame5, text='Permission 3')
        self.label_frame5_error = tk.Label(self.frame5, text='Role already exists')
        self.label_frame6_role_name = tk.Label(self.frame6, text='Role Name')
        self.label_frame6_error = tk.Label(self.frame6, text='Role does not exist')
        self.label_google = tk.Label(self.frame8, text='Google', fg='blue', cursor='hand2')
        self.label_facebook = tk.Label(self.frame8, text='Facebook', fg='blue', cursor='hand2')
        self.label_amazon = tk.Label(self.frame8, text='Amazon', fg='blue', cursor='hand2')
        self.label_blackboard = tk.Label(self.frame8, text='Blackboard', fg='blue', cursor='hand2')
        self.label_econnection = tk.Label(self.frame8, text='eConnection', fg='blue', cursor='hand2')

        self.entry_frame1_username = tk.Entry(self.frame1, textvariable=self.ctrl_username)
        self.entry_frame1_password = tk.Entry(self.frame1, show='*', textvariable=self.ctrl_password)
        self.entry_frame3_username = tk.Entry(self.frame3, textvariable=self.ctrl_username)
        self.entry_frame3_password = tk.Entry(self.frame3, show='*', textvariable=self.ctrl_password)
        self.entry_frame4_username = tk.Entry(self.frame4, textvariable=self.ctrl_username)
        self.entry_frame5_role_name = tk.Entry(self.frame5, textvariable=self.ctrl_role_name)
        self.entry_link1 = tk.Entry(self.frame5, textvariable=self.ctrl_link1)
        self.entry_link2 = tk.Entry(self.frame5, textvariable=self.ctrl_link2)
        self.entry_link3 = tk.Entry(self.frame5, textvariable=self.ctrl_link3)
        self.entry_frame6_role_name = tk.Entry(self.frame6, textvariable=self.ctrl_role_name)

        self.button_login = tk.Button(self.frame1, text='Login')
        self.button_logout = tk.Button(self.frame2, text='Logout')
        self.button_add_user = tk.Button(self.frame2, text='Add User')
        self.button_remove_user = tk.Button(self.frame2, text='Remove User')
        self.button_add_role = tk.Button(self.frame2, text='Add Role')
        self.button_remove_role = tk.Button(self.frame2, text='Remove Role')
        self.button_link1 = tk.Button(self.frame2)
        self.button_frame3_add = tk.Button(self.frame3, text='Add')
        self.button_frame3_back = tk.Button(self.frame3, text='Back')
        self.button_frame4_remove = tk.Button(self.frame4, text='Remove')
        self.button_frame4_back = tk.Button(self.frame4, text='Back')
        self.button_frame5_add = tk.Button(self.frame5, text='Add')
        self.button_frame5_back = tk.Button(self.frame5, text='Back')
        self.button_frame6_remove = tk.Button(self.frame6, text='Remove')
        self.button_frame6_back = tk.Button(self.frame6, text='Back')

        self.button_login.config(command=lambda button=self.button_login: self.on_click(button))
        self.button_logout.config(command=lambda button=self.button_logout: self.on_click(button))
        self.button_add_user.config(command=lambda button=self.button_add_user: self.on_click(button))
        self.button_remove_user.config(command=lambda button=self.button_remove_user: self.on_click(button))
        self.button_add_role.config(command=lambda button=self.button_add_role: self.on_click(button))
        self.button_remove_role.config(command=lambda button=self.button_remove_role: self.on_click(button))
        self.button_link1.config(command=lambda button=self.button_link1: self.on_click(button))
        self.button_frame3_add.config(command=lambda button=self.button_frame3_add: self.on_click(button))
        self.button_frame3_back.config(command=lambda button=self.button_frame3_back: self.on_click(button))
        self.button_frame4_remove.config(command=lambda button=self.button_frame4_remove: self.on_click(button))
        self.button_frame4_back.config(command=lambda button=self.button_frame4_back: self.on_click(button))
        self.button_frame5_add.config(command=lambda button=self.button_frame5_add: self.on_click(button))
        self.button_frame5_back.config(command=lambda button=self.button_frame5_back: self.on_click(button))
        self.button_frame6_remove.config(command=lambda button=self.button_frame6_remove: self.on_click(button))
        self.button_frame6_back.config(command=lambda button=self.button_frame6_back: self.on_click(button))

        self.label_google.bind('<Button-1>', lambda event, link=self.label_google: self.open_link(link))
        self.label_facebook.bind('<Button-1>', lambda event, link=self.label_facebook: self.open_link(link))
        self.label_amazon.bind('<Button-1>', lambda event, link=self.label_amazon: self.open_link(link))
        self.label_blackboard.bind('<Button-1>', lambda event, link=self.label_blackboard: self.open_link(link))
        self.label_econnection.bind('<Button-1>', lambda event, link=self.label_econnection: self.open_link(link))


        self.grid(sticky=tk.NSEW)
        self.make_frame1()

    def open_link(self, link):
        if link is self.label_google:
            webbrowser.open_new(r'google.com')
        elif link is self.label_facebook:
            webbrowser.open_new(r'facebook.com')
        elif link is self.label_amazon:
            webbrowser.open_new(r'smile.amazon.com')
        elif link is self.label_blackboard:
            webbrowser.open_new(r'blackboard.com')
        elif link is self.label_econnection:
            webbrowser.open_new(r'career.egr.uh.edu/students/econnection')
        else:
            webbrowser.open_new(self.urls.get(link))

    def on_click(self, button):
        if button is self.button_login:
            username = self.ctrl_username.get()
            password = self.ctrl_password.get()
            verified = self.database.authenticate_user(username, password)
            if verified:
                roles = self.database.username_roles[username]
                user = db.User(username, password, roles)
                self.current_user = user
                self.frame1.grid_forget()
                self.make_frame2()
            else:
                self.label_frame1_error.grid(column=0, row=2, columnspan=self.frame1.grid_size()[0])

        if button is self.button_logout:
            self.frame2.grid_forget()
            self.make_frame1()

        if button is self.button_add_user:
            self.frame2.grid_forget()
            self.make_frame3()

        if button is self.button_remove_user:
            self.frame2.grid_forget()
            self.make_frame4()

        if button is self.button_add_role:
            self.frame2.grid_forget()
            self.make_frame5()

        if button is self.button_remove_role:
            self.frame2.grid_forget()
            self.make_frame6()

        if button is self.button_frame3_add:
            username = self.ctrl_username.get()
            password = self.ctrl_password.get()

            roles = []
            num_check_buttons = len(self.check_buttons)
            for i in range(num_check_buttons):
                if self.ctrl_checks[i].get() == 1:
                    role = list(self.database.role_permissions.keys())[i]
                    roles.append(role)

            new_user = db.User(username, password, roles)
            result = self.database.add_user(new_user)
            if result == db.Database.RESULT_SUCCESS:
                self.ctrl_username.set('')
                self.ctrl_password.set('')
                self.label_frame3_error.grid_forget()
            else:
                self.label_frame3_error.grid(column=0, row=2, columnspan=self.frame3.grid_size()[0])

            for ctrl_check in self.ctrl_checks:
                ctrl_check.set(0)

        if button is self.button_frame3_back:
            self.frame3.grid_forget()
            self.make_frame2()

        if button is self.button_frame4_remove:
            username = self.ctrl_username.get()
            result = self.database.remove_user(username)
            if result == db.Database.RESULT_SUCCESS:
                self.ctrl_username.set('')
                self.label_frame4_error.grid_forget()
            else:
                self.label_frame4_error.grid(column=0, row=2, columnspan=self.frame1.grid_size()[0])

        if button is self.button_frame4_back:
            self.frame4.grid_forget()
            self.make_frame2()

        if button is self.button_frame5_add:
            role_name = self.ctrl_role_name.get()
            link1 = self.ctrl_link1.get()
            link2 = self.ctrl_link2.get()
            link3 = self.ctrl_link3.get()

            links = []
            if link1 != '' and link1 not in links:
                links.append(link1)
            if link2 != '' and link2 not in links:
                links.append(link2)
            if link3 != '' and link3 not in links:
                links.append(link3)

            result = self.database.add_role(role_name, links)
            if result == db.Database.RESULT_SUCCESS:
                self.ctrl_role_name.set('')
                self.ctrl_link1.set('')
                self.ctrl_link2.set('')
                self.ctrl_link3.set('')
                self.label_frame5_error.grid_forget()
            else:
                self.label_frame5_error.grid(column=0, row=2)

        if button is self.button_frame5_back:
            self.frame5.grid_forget()
            self.make_frame2()

        if button is self.button_frame6_remove:
            role_name = self.ctrl_role_name.get()
            result = self.database.remove_role(role_name)
            if result == db.Database.RESULT_SUCCESS:
                self.ctrl_role_name.set('')
                self.label_frame6_error.grid_forget()
            else:
                self.label_frame6_error.grid(column=0, row=2, columnspan=self.frame6.grid_size()[0])

        if button is self.button_frame6_back:
            self.frame6.grid_forget()
            self.frame2.grid(sticky=tk.NSEW)

    def make_frame1(self):
        self.frame1.grid(sticky=tk.NSEW)
        self.label_frame1_username.grid(column=0, row=0)
        self.label_frame1_password.grid(column=1, row=0)
        self.entry_frame1_username.grid(column=0, row=1)
        self.entry_frame1_password.grid(column=1, row=1)
        self.button_login.grid(column=2, row=1)

        self.ctrl_username.set('')
        self.ctrl_password.set('')
        self.label_frame1_error.grid_forget()

    def make_frame2(self):
        self.frame2.grid(sticky=tk.NSEW)

        if self.database.verify_permission(self.current_user, 'add_remove_user'):
            self.button_add_user.grid(column=0, row=0)
            self.button_remove_user.grid(column=1, row=0)
        else:
            self.button_add_user.grid_forget()
            self.button_remove_user.grid_forget()
        if self.database.verify_permission(self.current_user, 'add_remove_role'):
            self.button_add_role.grid(column=0, row=1)
            self.button_remove_role.grid(column=1, row=1)
        else:
            self.button_add_role.grid_forget()
            self.button_remove_role.grid_forget()
        if self.database.verify_permission(self.current_user, 'blackboard'):
            self.label_blackboard.grid(column=0, row=3)
        else:
            self.label_blackboard.grid_forget()
        if self.database.verify_permission(self.current_user, 'econnection'):
            self.label_econnection.grid(column=0, row=4)
        else:
            self.label_econnection.grid_forget()

        #for adding new links to frame2
        for label in self.newlinks:
            label.grid_forget()
        self.newlinks.clear()
        self.urls.clear()
        i = 5
        for self.permission in self.database.role_permissions:
            for self.roles in self.current_user.roles:
                if self.roles == self.permission:
                    for self.role in self.database.role_permissions[self.permission]:
                        if self.role == 'econnection' or self.role == 'blackboard' or self.role == 'add_remove_role' or self.role == 'add_remove_user':
                            continue
                        else:
                            self.label_unknown = tk.Label(self.frame8, text=self.role[:self.role.find('.')].capitalize(), fg='blue', cursor='hand2')
                            self.newlinks.append(self.label_unknown)     #place label last
                            self.newlinks[-1].grid(column = 0, row = i) #last label in list
                            self.urls.update({self.label_unknown:self.role})
                            i += 1

        for self.labels in self.newlinks: #binding new links to a website
            self.labels.bind('<Button-1>', lambda event, link=self.labels: self.open_link(link))


        # Global Links
        self.frame8.grid(column=0, row=2, columnspan=self.frame2.grid_size()[0])
        self.label_google.grid(column=0, row=0)
        self.label_facebook.grid(column=0, row=1)
        self.label_amazon.grid(column=0, row=2)
        self.button_logout.grid(column=0, row=5, columnspan=self.frame2.grid_size()[0])

    def make_frame3(self):
        self.frame3.grid(sticky=tk.NSEW)
        self.label_frame3_username.grid(column=0, row=0)
        self.label_frame3_password.grid(column=1, row=0)
        self.entry_frame3_username.grid(column=0, row=1)
        self.entry_frame3_password.grid(column=1, row=1)
        self.button_frame3_add.grid(column=2, row=1)
        self.frame7.grid(column=0, row=3, columnspan=self.frame3.grid_size()[0])
        self.button_frame3_back.grid(column=0, row=4, columnspan=self.frame3.grid_size()[0])

        for check_button in self.check_buttons:
            check_button.grid_forget()

        for ctrl_check in self.ctrl_checks:
            ctrl_check.set(0)

        num_roles = len(self.database.role_permissions)
        for i in range(num_roles):
            self.check_buttons[i].grid(column=0, row=i)
            text = list(self.database.role_permissions.keys())[i]
            self.check_buttons[i].config(text=text)

        self.ctrl_username.set('')
        self.ctrl_password.set('')
        self.label_frame3_error.grid_forget()

    def make_frame4(self):
        self.frame4.grid(sticky=tk.NSEW)
        self.label_frame4_username.grid(column=0, row=0)
        self.entry_frame4_username.grid(column=0, row=1)
        self.button_frame4_remove.grid(column=1, row=1)
        self.button_frame4_back.grid(column=0, row=3, columnspan=self.frame4.grid_size()[0])

        self.ctrl_username.set('')
        self.label_frame4_error.grid_forget()

    def make_frame5(self):
        self.frame5.grid(sticky=tk.NSEW)
        self.label_frame5_role_name.grid(column=0, row=0)
        self.entry_frame5_role_name.grid(column=0, row=1)
        self.button_frame5_add.grid(column=0, row=3)
        self.button_frame5_back.grid(column=0, row=4)
        self.label_permission1.grid(column=1, row=0)
        self.entry_link1.grid(column=1, row=1)
        self.label_permission2.grid(column=1, row=2)
        self.entry_link2.grid(column=1, row=3)
        self.label_permission3.grid(column=1, row=4)
        self.entry_link3.grid(column=1, row=5)

        self.ctrl_role_name.set('')
        self.ctrl_link1.set('')
        self.ctrl_link2.set('')
        self.ctrl_link3.set('')
        self.label_frame5_error.grid_forget()

    def make_frame6(self):
        self.frame6.grid(sticky=tk.NSEW)
        self.label_frame6_role_name.grid(column=0, row=0)
        self.entry_frame6_role_name.grid(column=0, row=1)
        self.button_frame6_remove.grid(column=1, row=1)
        self.button_frame6_back.grid(column=0, row=3, columnspan=self.frame6.grid_size()[0])

        self.ctrl_role_name.set('')
        self.label_frame6_error.grid_forget()


def main():
    app = Application()
    app.master.title('Portal')
    app.database.add_role('admin', ['add_remove_user', 'add_remove_role'])
    ryan = db.User('ryan', '1234', ['admin'])
    kunle = db.User('kunle', '12345', ['admin'])
    app.database.add_user(kunle)
    app.database.add_user(ryan)
    app.mainloop()

if __name__ == '__main__':
    main()
