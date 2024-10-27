from flask_login import current_user

class CheckRole:
    def __init__(self,record=None):
        self.record = record
        
    def create(self):
        return current_user.is_admin()
    
    def edit(self):
        return current_user.is_admin() or current_user.is_moder()
    
    def delete(self):
        return current_user.is_admin()
    
    def show(self):
        return current_user.is_admin() or current_user.is_user()
    
    def add(self):
        return current_user.is_admin() or current_user.is_user()