# seed_data.py

import models
from sqlalchemy.orm import Session
from database import SessionLocal

db : Session = SessionLocal()

permissions_name = [
    'add_role',
    'add_permission',
    'update_profile',
    'change_password',
    'change_status',
    'view_users',
    'delete_user',
    'verify'
]

existing_permissions = {p.name for p in db.query(models.Permission).all()}
for perm in permissions_name:
    if perm not in existing_permissions:
        db.add(models.Permission(name=perm))

db.commit()
admin_role = db.query(models.Role).filter_by(name="admin").first()
user_role = db.query(models.Role).filter_by(name="user").first()
viewer_role = db.query(models.Role).filter_by(name='viewer').first()

if not admin_role:
    admin_role = models.Role(name='admin')
    db.add(admin_role)

if not user_role:
    user_role = models.Role(name='user')
    db.add(user_role)

if not viewer_role:
    viewer_role = models.Role(name='viewer')
    db.add(viewer_role)

db.commit()

admin_permissions = db.query(models.Permission).all()
user_permissions = db.query(models.Permission).filter(models.Permission.name.in_(['update_profile','change_password','verify'])).all()
viewer_permissions = db.query(models.Permission).filter(models.Permission.name.in_(['view_users','verify'])).all()

admin_role.permissions = admin_permissions
user_role.permissions = user_permissions
viewer_role.permissions = viewer_permissions

db.commit()
db.close()




