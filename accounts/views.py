from datetime import datetime, timedelta
from random import randint
from django.conf import settings
from django.forms import model_to_dict
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from knox.models import AuthToken
from rest_framework import generics, status
from django.db import IntegrityError
from django.utils import timezone
from django.db.models import Q, ProtectedError
from models_logging.models import Change
from django.utils.timezone import utc
from django.http import Http404
from django.core.mail import send_mail
from django.core.validators import EmailValidator
from django.core.exceptions import ValidationError
from cryptography.fernet import Fernet, InvalidToken
from django.template.loader import render_to_string
import dotenv
import os
from django.contrib.auth.hashers import make_password


# local imports
from custom.permissions import isAdmin, isSuperuser
from accounts.models import Admin, AdminMenu, AdminMenuAccess, AdminOTP, Member, MembershipRequest, MembershipType, User
from accounts.serializers import AdminMenuSerializer, AdminSerializer, AdminSignInSerializer, ChangesLogAPISerializer, MembershipRequestSerializer

#
dotenv.load_dotenv()
#
fernet = Fernet(os.getenv('crypt_key'))
#


class AdminSignInView(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request, format=None):
        serializer = AdminSignInSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        token_obj, token = AuthToken.objects.create(user=user)
        expiry = timezone.localtime(token_obj.expiry)
        User.objects.filter(id=user.id).update(
            last_login=datetime.now(tz=timezone.utc))
        if user.admin.admin_email_verified:
            email_verified = True
        else:
            email_verified = False
        return Response({"success": True, "message": "Login Successful", "email_verified": email_verified, "token": token, "login_expiry": expiry, "preferences": {}})


# Check Token Valid:
class CheckTokenAPI(generics.GenericAPIView):
    def get(self, request):
        if request.user.admin.admin_email_verified == False:
            return Response({"success": False, "message": "Verify Email Address"})
        return Response({"success": True, "message": "User already logged in"})


# Get Admin user info:
class AdminInfo(generics.GenericAPIView):
    permission_classes = [isAdmin]

    def post(self, request, *args, **kwargs):
        try:
            admin = Admin.objects.get(user=request.user)
        except Admin.DoesNotExist:
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        # if admin.admin_email_verified == False:
        #     return Response({"error_detail": ['Admin User need to verify email first']}, status=status.HTTP_403_FORBIDDEN)
        expiry = timezone.localtime(AuthToken.objects.get(
            token_key=request.auth.token_key).expiry)
        data = {"user": {"username": request.user.username, "admin_name": admin.name,
                         "admin_email": request.user.email,
                         "login_expiry": expiry, "admin_email_verified": admin.admin_email_verified}}
        return Response({"data": data})


# Admin Change Password API:
class AdminChangePassword(generics.GenericAPIView):
    permission_classes = [isAdmin]

    def post(self, request, *args, **kwargs):
        user = (request.user)
        if (request.data['old_password'] == request.data['new_password']):
            return Response({"error_detail": ['New Password and Old password cant be same']}, status=status.HTTP_400_BAD_REQUEST)
        if bool(user.check_password(request.data['old_password'])) == False:
            return Response({"error_detail": ['Incorrect password entered as Current Password']}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(request.data['new_password'])
        user.save()
        # Delete all  Tokens of this user to logout from other Devices other than This Device/Browser --
        AuthToken.objects.filter(user=user).exclude(
            token_key=request.auth.token_key).delete()
        return Response({"message": "Password changed successfully"})


# Update Admin by self
class AdminChange(generics.GenericAPIView):
    permission_classes = [isAdmin]

    def post(self, request, *args, **kwargs):
        user = (request.user)
        data = request.data.copy()
        request.data.pop('email')

        # Case - When OTP is entered with other data to  save email
        if ('email_otp' in request.data):
            # Delete Expired OTPs of all users.  || Later:  Need to check case of Valid OTPs of this User other than email in request
            AdminOTP.objects.filter(expiry__lt=timezone.now()).delete()
            ##
            try:
                latest_otp = AdminOTP.objects.filter(
                    admin=request.user.admin, email_id=data['email'], otp_for=1, expiry__gte=timezone.now()).latest('creation_time')
                if (latest_otp.otp_code == request.data['email_otp']):
                    try:
                        user.email = data['email']
                        user.save()
                    except IntegrityError:
                        return Response({"error_detail": ['Email already associated with another account']}, status=status.HTTP_400_BAD_REQUEST)
                    request.user.admin.name = request.data['name']
                    request.user.admin.save()
                    # Delete this OTP because its usage is over.
                    latest_otp.delete()
                    # Delete OTP related with user & email
                    AdminOTP.objects.filter(
                        admin=request.user.admin, email_id=data['email']).delete()  # / mutli request scenario
                    return Response({"success": True, 'message': "Profile updated with email being successfully verified"})
                else:
                    raise AdminOTP.DoesNotExist
            except AdminOTP.DoesNotExist:
                return Response({"error_detail": ['OTP entered is incorrect']}, status=status.HTTP_400_BAD_REQUEST)

        # Case - When Email is changed... OTP is sent to verify the email
        if (user.email != data['email']):
            if User.objects.filter(
                    email=data['email']).exclude(id=user.pk).exists():
                return Response({"error_detail": ['Email already associated with another account']}, status=status.HTTP_400_BAD_REQUEST)

            otp = (randint(100000, 999999))
            message = f'\n{request.user.admin.name}, \n We received a request to update your email on the Jewellery Association Admin. Please use the OTP {otp} to verify this email and complete the process.OTP is valid for 2 minutes only.'
            subject = "One Time Password to Verify your Email Address"
            # MODE - WHEN EMAIL IS CHANGED by SELF- OTP is sent
            AdminOTP.objects.create(admin=request.user.admin, otp_code=otp,
                                    expiry=timezone.now() + timedelta(minutes=2), email_id=data['email'], otp_for=1)
            html_message = render_to_string('verify_email_otp.html', {
                "name": request.user.admin.name, "code": otp})
            send_mail(subject=subject, message=message, html_message=html_message,
                      from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[data['email']])
            return Response({"success": True, "message": "Email verification Required"}, status=status.HTTP_200_OK)

        # Case - When Only Admin Name is Changed
        request.user.admin.name = request.data['name']
        request.user.admin.save()
        return Response({"success": True, "message": "Profile Updated"}, status=status.HTTP_200_OK)


# Create Admin OTP:
class AdminOTPCreate(generics.GenericAPIView):
    permission_classes = [isAdmin]

    def post(self, request, *args, **kwargs):
        email = request.data['email']
        otp_for = request.data['otp_for']
        try:
            EmailValidator()(email)
        except ValidationError:
            return Response({"error_detail": ['Invalid email format']}, status=status.HTTP_400_BAD_REQUEST)
        if (User.objects.filter(Q(email=email)).exclude(id=request.user.id).exists()):
            return Response({"error_detail": ['Email already associated with another account']}, status=status.HTTP_400_BAD_REQUEST)
        otp = (randint(100000, 999999))
        # MODE - CREATE ADMIN OTP - now for Email verification for superadmin changed mail - / 1. profile change / 2.verification
        AdminOTP.objects.create(otp_for=otp_for, admin=request.user.admin, otp_code=otp,
                                expiry=timezone.now() + timedelta(minutes=2), email_id=email)
        message = f'\n{request.user.admin.name}, \n We received a request to update your email on the Jewellery Association Admin. Please use the OTP {otp} to verify this email and complete the process.OTP is valid for 2 minutes only.'
        html_message = render_to_string('verify_email_otp.html', {
                                        "name": request.user.admin.name, "code": otp})
        subject = "One Time Password to Verify your Email Address"
        send_mail(html_message=html_message, subject=subject, message=message,
                  from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[email])
        return Response({'message': "OTP created and is sent to your email"})


# Verify Admin OTP:
class AdminOTPVerify(generics.GenericAPIView):
    permission_classes = [isAdmin]

    def post(self, request, *args, **kwargs):
        if 'email_otp' in request.data:
            # Delete Expired OTPs of all users.  || Later:  Need to check case of Valid OTPs of this User other than email in request
            AdminOTP.objects.filter(expiry__lt=timezone.now()).delete()
            try:
                # otp  for  -- "2", "Email Verify OTP" - change if any other scenario uses this API view
                latest_otp = AdminOTP.objects.filter(
                    admin=request.user.admin, otp_for=2, email_id=request.data['email'], expiry__gte=timezone.now()).latest('creation_time')
                if (latest_otp.otp_code == request.data['email_otp']):
                    request.user.admin.admin_email_verified = True
                    request.user.admin.save()
                    # Delete this OTP because its usage is over.
                    latest_otp.delete()
                    # Delete OTP related with user & email
                    AdminOTP.objects.filter(
                        admin=request.user.admin, email_id=request.data['email']).delete()  # / mutli request scenario
                    return Response({'message': "OTP verified"})
                else:
                    raise AdminOTP.DoesNotExist
            except AdminOTP.DoesNotExist:
                return Response({"error_detail": ['OTP entered is incorrect']}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error_detail": ['Invalid Request']}, status=status.HTTP_400_BAD_REQUEST)


# Reset Admin Password:
class AdminResetPassword(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        if 'reset_password' in request.data:
            try:
                try:
                    EmailValidator()(request.data['user'])
                    user = User.objects.filter(is_adminuser=True).get(
                        email=request.data['user'])
                except:
                    user = User.objects.filter(is_adminuser=True).get(
                        username=request.data['user'])
                #
                # check if already a reset link/otp request exists with expiry time still left
                if (AdminOTP.objects.filter(admin=user.admin, otp_for=0, email_id=user.email, expiry__gt=timezone.now()).exists()):
                    return Response({"error_detail": ["A valid reset link already exists. Please use it / wait till its expiry"]}, status=status.HTTP_400_BAD_REQUEST)
                #
                subject = "Link to reset your Password"
                origin = request.data['origin']
                OTP_code = randint(100000, 999999)
                encOTP = fernet.encrypt(str(OTP_code).encode())
                # MODE - ADMIN PASSWORD RESET / FORGOT
                AdminOTP.objects.create(admin=user.admin, otp_for=0, email_id=user.email,
                                        otp_code=OTP_code, expiry=timezone.now()+timedelta(minutes=5))
                message = f"Visit this link to confirm your willingness to reset your password and to enter new password : \n {origin}/auth-reset/confirm_reset/{encOTP.decode()} . \n This link is valid for next 5 minutes only"
                html_message = render_to_string(
                    'reset_email_template.html', {'origin': origin, "encOTP": encOTP, "name": user.admin.name, "account_type": "Admin", "path": "auth-reset/confirm_reset"})
                send_mail(subject=subject, message=message,
                          from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[user.email], html_message=html_message)
                # delete old OTPs created for passsword reset
                AdminOTP.objects.filter(
                    admin=user.admin,  otp_for=0, expiry__lt=timezone.now()).delete()
                return Response({"success": True, "message": "Email with reset link has been sent"})
            except User.DoesNotExist:
                return Response({"error_detail": ["No User Found with provided details"]}, status=status.HTTP_400_BAD_REQUEST)
        if 'change_password' in request.data:
            # passing invalid OTP/encrypted code ... / if code is malfunctioned
            try:
                decOTP = fernet.decrypt(
                    request.data['reset_code'].encode('utf-8')).decode()
            except InvalidToken:
                return Response({"error_detail": ["Invalid password reset link. Please request reset link again "]}, status=status.HTTP_400_BAD_REQUEST)
            #
            if (AdminOTP.objects.filter(otp_code=decOTP, otp_for=0,
                                        expiry__gte=timezone.now()).exists()):
                instance = AdminOTP.objects.get(otp_code=decOTP)
                user = instance.admin.user
                user.set_password(request.data['passwd'])
                user.save()
                # delete used OTP:
                instance.delete()
                # Delete users all tokens:
                AuthToken.objects.filter(user=user).delete()
                return Response({"success": True, 'message': "Password is reset successfully"})
            return Response({"error_detail": ["Invalid/Expired link used. Please request reset link again"]}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error_detail": []}, status=status.HTTP_400_BAD_REQUEST)


# Listcreate api for  AdminMenus in Admin panel


class AdminMenuList(generics.ListCreateAPIView):
    permission_classes = [isAdmin]
    serializer_class = AdminMenuSerializer
    queryset = AdminMenu.objects.all()

    def get(self, request, *args, **kwargs):
        if 'options' in request.query_params:
            queryset = self.get_queryset()
            serializer = self.get_serializer(queryset, many=True)
            output = []
            output.append({"value": None, "label": "Home"})
            for data in serializer.data:
                if (data['parent'] == None):
                    instance = {}
                    instance.update(
                        {"value": data['id'], "label": data['text']})
                    if instance not in output:
                        output.append(instance)

            return Response(output)
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        for data in serializer.data:
            data.update({"submenus": 0})
            if data['parent'] == None or data['parent'] == data['id']:
                data.update({"parent_page": "Home"})
            else:
                try:
                    parent_page = AdminMenu.objects.get(id=data['parent']).text
                    data.update({"parent_page": parent_page})
                except AdminMenu.DoesNotExist:
                    data.update({"parent_page": None})
            for each in serializer.data:
                # print(each != data)
                if (each != data):
                    # print(each['parent']==data["id"])
                    if (each['parent'] == data["id"]):
                        data['submenus'] += 1
            # data.pop("ownership")
            data.pop("icon")
        return Response(
            sorted(serializer.data, key=lambda k: k['id'], reverse=True))

    def post(self, request, *args, **kwargs):
        menu_links = [each.link for each in AdminMenu.objects.all()]
        if 'link' in request.data:
            if request.data['link'] != '#':
                if (len(request.data['link']) > 1):
                    request.data['link'] = request.data['link'].rstrip("/")
                if request.data['link'] in menu_links:
                    return Response(
                        {"error_detail": [
                            'Menu with this link already exist']},
                        status=status.HTTP_400_BAD_REQUEST)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        for each in Admin.objects.all():
            AdminMenuAccess.objects.create(
                admin=each, menu_id=serializer.data['id'])
        return Response(serializer.data, status=status.HTTP_201_CREATED)


# RetrieveUpdateDestroy  api for  AdminMenu entries in Admin panel
class AdminMenuDetails(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [isAdmin]
    serializer_class = AdminMenuSerializer
    queryset = AdminMenu.objects.all()

    def get(self, request, *args, **kwargs):
        admin_menu = self.get_object()
        serializer = self.get_serializer(admin_menu)
        instance = serializer.data
        if instance['parent'] != None:
            menu_id = admin_menu.parent.id
            menu_name = admin_menu.parent.text
            # print("menu_id", menu_id, "menu_name", menu_name)
            instance.update(
                {'parent': {"label": menu_name, "value": menu_id}})
        else:
            instance.update({'parent': {"label": "Home", "value": None}})

        return Response(instance)

    def put(self, request, *args, **kwargs):
        menu_links = [
            each.link for each in AdminMenu.objects.filter(~Q(
                id=kwargs['pk']))
        ]
        if 'link' in request.data:
            if request.data['link'] != '#':
                if (len(request.data['link']) > 1):
                    request.data['link'] = request.data['link'].rstrip(
                        "/")
                    if request.data['link'] in menu_links:
                        return Response(
                            {"error_detail": [
                                "Menu with this link already exist"]},
                            status=status.HTTP_400_BAD_REQUEST)
        admin_menu = self.get_object()
        serializer = self.get_serializer(admin_menu, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


# Admin List/Create API
class AdminCRUDAPI(generics.GenericAPIView):
    permission_classes = [isSuperuser]
    serializer_class = AdminSerializer
    queryset = Admin.objects.all()

    def get(self, request, *args, **kwargs):
        if ('pk' in kwargs):
            admin = (self.get_object())
            # hide Super User admin
            if (admin.user.is_superuser):
                raise Http404
            accessdata = []
            for each in (AdminMenuAccess.objects.filter(
                    admin=admin)):
                menu_item = {}
                menu_item.update({'id': each.menu.pk, 'text': each.menu.text, "order": each.menu.order, 'parent_id': each.menu.parent.pk if each.menu.parent != None else None, 'view': each.view,
                                 "add": each.add, "edit": each.edit, "delete": each.delete})
                accessdata.append(menu_item)
            sortbyorder = sorted(accessdata,
                                 key=lambda k:
                                 (k['order'], k['id']))
            # To get the count of sub menus of parent
            for each in sortbyorder:
                each.update({"submenus": 0})
                for each1 in sortbyorder:
                    if (each1 != each):
                        # print('Parent', each1['parent_id'])
                        if (each1['parent_id'] == each["id"]):
                            each['submenus'] += 1
                # Create a new list with parent menu then its child menu  in order
            new_order = []
            for each in sortbyorder:
                #  if no child and {condition checked whether parent is Root / home  or Parent is item itself} add the item to list
                if (each['submenus']
                        == 0) and (each['parent_id'] == None
                                   or each['parent_id'] == each['id']):
                    # if each not in new_order:
                    new_order.append(each)
                    continue
                # if the Item  has children Menu items
                if (each['submenus'] > 0):
                    # first add the item to new list
                    new_order.append(each)
                    # Search the children of the item by looping again
                    for submen in sortbyorder:
                        if each['id'] == submen['parent_id']:
                            # append the child to the new list
                            new_order.append(submen)
            output = {"admin": {"name": admin.name, "username": admin.user.username,
                                "email": admin.user.email, "is_active": admin.user.is_active}, "accessdata": new_order, "dasboard_access": []}
            return Response(output)
        output = []
        # Non Super User Admins
        queryset = self.get_queryset().filter(user__is_superuser=0)
        for each in queryset:
            admin = {"adminid": each.adminid, "name": each.name,
                     "username": each.user.username, "email": each.user.email, "is_active": each.user.is_active}
            if admin not in output:
                output.append(admin)

        return Response(output)

    def post(self, request, *args, **kwargs):
        if ('pk' in kwargs):
            return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)
        # > CREATE ADMIN
        admin_name = request.data['admin'].pop('name')
        password = request.data['admin'].pop('password')
        # create a user
        request.data['admin'].update({'is_adminuser': True})
        try:
            user = User.objects.create(**request.data['admin'])
        except IntegrityError as e:
            if "Invalid username" in str(e):
                return Response({"error_detail": ["Invalid username"]}, status=status.HTTP_400_BAD_REQUEST)
            if ("users.username" in str(e)):
                return Response({"error_detail": ['Username already allocated']}, status=status.HTTP_400_BAD_REQUEST)
            if ("users.users_email" in str(e)):
                return Response({"error_detail": ['Email already allocated']}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(password)
        user.save()
        # create admin using user
        admin = Admin.objects.create(name=admin_name, user=user)
        # create Admin menu access for created Admin
        for each in request.data['accessdata']:
            each.update({"admin": admin})
            AdminMenuAccess.objects.create(**each)
        return Response({"success": True, "message": "Admin user created successfully"}, status=status.HTTP_201_CREATED)

    def put(self, request, *args, **kwargs):
        if ('pk' in kwargs):
            admin = self.get_object()
            # super user Admin is not editable
            if (admin.user.is_superuser):
                return Response({"error_detail": ["You are not allowed to perform this action"]}, status=status.HTTP_403_FORBIDDEN)
            admin.name = request.data['admin']['name']
            user = admin.user
            try:
                user.username = request.data['admin']['username']
                # If a new mail ID is used set email verified status as False
                if user.email != request.data['admin']['email']:
                    user.email = request.data['admin']['email']
                    admin.admin_email_verified = False
                user.is_active = request.data['admin']['is_active']
                if (request.data['admin']['changepass']):
                    user.set_password(request.data['admin']['password'])
                user.save()
            except IntegrityError as e:
                if "Invalid username" in str(e):
                    return Response({"error_detail": ["Invalid username"]}, status=status.HTTP_400_BAD_REQUEST)
                if ("users.username" in str(e)):
                    return Response({"error_detail": ['Username already in use.']}, status=status.HTTP_400_BAD_REQUEST)
                if ("users.email" in str(e)):
                    return Response({"error_detail": ['Email already allocated for another user']}, status=status.HTTP_400_BAD_REQUEST)
            admin.save()
            for access in request.data['accessdata']:
                AdminMenuAccess.objects.filter(
                    menu_id=access['id'], admin=admin.pk).update(view=access['view'], add=access['add'], edit=access['edit'], delete=access['delete'])
            # delete tokens of edited user:
            AuthToken.objects.filter(user=user).delete()
            return Response({"success": True, "message": "Admin user updated successfully"}, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        if ('pk' in kwargs):
            # print(request.user)
            admin = self.get_object()
            if (admin.user.is_superuser):
                return Response({"error_detail": ["This Admin is a superuser, can't be deleted..."]}, status=status.HTTP_400_BAD_REQUEST)
            user = admin.user
            try:
                admin.delete()
                user.delete()
            except ProtectedError:
                return Response({"error_detail": ["Can't delete. Admin has items associated to him"]}, status=status.HTTP_423_LOCKED)
            return Response({"success": True, "message": "Admin user deleted"}, status=status.HTTP_204_NO_CONTENT)
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)


# Admin Menu List/Create API
class AdminMenuFetch(generics.GenericAPIView):
    permission_classes = [isAdmin]
    queryset = AdminMenu.objects.all()
    serializer_class = AdminMenuSerializer

    def get(self, request, *args, **kwargs):
        queryset = self.get_queryset().filter(active=True)
        if 'options' in request.query_params:
            menu_access = queryset.values()
            # Sort Order by a combo of Order and Primary
            sortbyorder = sorted(menu_access,
                                 key=lambda k:
                                 (k['order'], k['id']))

            # To get the count of sub menus of parent
            for each in sortbyorder:
                each.update({"submenus": 0, "view": 0,
                            "add": 0, "edit": 0, "delete": 0})
                # delete unused properties
                del each['link']
                del each['icon']
                del each['active']
                del each['title']
                del each['order']

                # print('Pk', each['id'])
                for each1 in sortbyorder:
                    if (each1 != each):
                        # print('Parent', each1['parent_id'])
                        if (each1['parent_id'] == each["id"]):
                            each['submenus'] += 1
                # Create a new list with parent menu then its child menu  in order
            new_order = []
            for each in sortbyorder:
                #  if no child and {condition checked whether parent is Root / home  or Parent is item itself} add the item to list
                if (each['submenus']
                        == 0) and (each['parent_id'] == None
                                   or each['parent_id'] == each['id']):
                    # if each not in new_order:
                    new_order.append(each)
                    continue
                # if the Item  has children Menu items
                if (each['submenus'] > 0):
                    # first add the item to new list
                    new_order.append(each)
                    # Search the children of the item by looping again
                    for submen in sortbyorder:
                        if each['id'] == submen['parent_id']:
                            # append the child to the new list
                            new_order.append(submen)
            return Response({"menu_access": new_order, "dasboard_access": []}, status=status.HTTP_200_OK)
        try:
            admin = Admin.objects.get(user=request.user)
        except Admin.DoesNotExist:
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        serializer = self.get_serializer(queryset, many=True)
        admin_menu_data = serializer.data
        sub_menu_data = []
        for data in serializer.data:
            # Filter Out Menu If the user does not have view permission/ is not superuser
            try:
                admin_menu_access = AdminMenuAccess.objects.get(
                    menu_id=data['id'], admin=admin)

                if (admin_menu_access.view or request.user.is_superuser) == False:
                    admin_menu_data.remove(data)
                    continue
            except AdminMenuAccess.DoesNotExist:
                admin_menu_data.remove(data)
                continue

            # if parent is assigned and not self parent -> create a sub menu list; and sub menu item is removed from the main menu list
            if data['parent'] != None and data['parent'] != data['id']:
                admin_menu_data.remove(data)
                sub_menu_data.append(data)
        # Sub menu are appended to their corresponding Parents:
        for menu in (serializer.data):
            if menu['parent'] == None or menu['parent'] == menu['id']:
                menu.update({"subMenu": []})
                for each in sub_menu_data:

                    if (menu['id'] == each['parent']):
                        menu['subMenu'].append(each)
                # if submenu empty : remove it from the menu item
                if (menu['subMenu'] == []):
                    menu.pop("subMenu")
                else:

                    menu['subMenu'] = sorted(menu['subMenu'],
                                             key=lambda k:
                                             (k['order'], k['id']))

        return Response(
            sorted(admin_menu_data, key=lambda k: (k['order'], k['id'])))


# check Access
class CheckAcess(generics.GenericAPIView):
    permission_classes = [isAdmin]

    def post(self, request, format=None):
        try:
            menu_access = AdminMenuAccess.objects.get(
                admin=request.user.admin, menu__link=request.data['path'])
            title = AdminMenu.objects.get(link=request.data['path']).title
            out = model_to_dict(menu_access)
            out.update(
                {"title": title, "is_superuser": False})
            # if super user.. give all permission irrespective of permissions set
            if request.user.is_superuser:
                out.update(
                    {"is_superuser": True, "view": True,
                     "add": True,
                     "edit": True,
                     "delete": True})
            return Response(out)
        except AdminMenuAccess.DoesNotExist:
            # if access not set / menu not created  / admin created manually in db ...
            # if super user.. give all permission
            if request.user.is_superuser:
                out = {
                    "is_superuser": True,
                    "view": True,
                    "add": True,
                    "edit": True,
                    "delete": True
                }
                return Response(out)
            # if not super user.. reject all permission
            out = {
                "is_superuser": False,
                "view": False,
                "add": False,
                "edit": False,
                "delete": False
            }
            return Response(out)


# Logs List API
class ChangesLogAPI(generics.GenericAPIView):
    permission_classes = [isAdmin]

    def get(self, request, format=None):
        queryset = Change.objects.all()
        format = '%Y-%m-%d %H:%M:%S.%f'
        if 'from' in request.query_params and 'to' in request.query_params and 'offset' in request.query_params:
            if request.query_params['from'] != None and request.query_params[
                    'from'] != 'null' and request.query_params[
                        'to'] != None and request.query_params['to'] != 'null' and request.query_params[
                        'offset'] != None and request.query_params['offset'] != 'null':
                offset = (request.query_params['offset'])
                offset_hrs = int(offset.lstrip(
                    '-'))//60
                offset_mins = int(offset.lstrip(
                    '-')) % 60
                #
                from_date = (datetime.strptime(
                    request.query_params['from'] + ' 0:0:0.0',
                    format)).replace(tzinfo=utc) + timedelta(hours=offset_hrs, minutes=offset_mins) if '-' in offset else (datetime.strptime(
                        request.query_params['from'] + ' 0:0:0.0',
                        format)).replace(tzinfo=utc) - timedelta(hours=offset_hrs, minutes=offset_mins)
                #
                to_date = (datetime.strptime(
                    request.query_params['to'] + ' 23:59:59.999999',
                    format)).replace(tzinfo=utc) + timedelta(hours=offset_hrs, minutes=offset_mins) if '-' in offset else (datetime.strptime(
                        request.query_params['to'] + ' 23:59:59.999999',
                        format)).replace(tzinfo=utc) - timedelta(hours=offset_hrs, minutes=offset_mins)
                #
                queryset = queryset.filter(date_created__lte=to_date,
                                           date_created__gte=from_date)
        serializer = ChangesLogAPISerializer(queryset, many=True)

        return Response(sorted(serializer.data, key=lambda i: i['id']),
                        status=status.HTTP_200_OK)


# Manage Membership request - membership which hasn't been approved till now
class MembershipsViewEdit(generics.GenericAPIView):
    permission_classes = [isAdmin]
    queryset = MembershipRequest.objects.filter(membership_is_approved=False)
    serializer_class = MembershipRequestSerializer

    def get(self, request, *args, **kwargs):
        if 'pk' in kwargs:
            # individual membership fetch
            return Response(self.get_serializer(self.get_object()).data)
        return Response((self.get_serializer(self.get_queryset(), many=True)).data)

    def put(self, request, *args, **kwargs):
        if 'pk' in kwargs:
            # Approving membership
            if 'membership_is_approved' in request.data:
                if request.data.get('membership_is_approved'):
                    obj = self.get_object()

                    # Create User
                    username = obj.member_email.split(
                        '@')[0] + (obj.member_mobile)[6:]

                    if (User.objects.filter(email=obj.member_email).exists()):
                        return Response({"error_detail": ["Email ID already in use."]}, status=status.HTTP_400_BAD_REQUEST)
                    if (Member.objects.filter(member_mobile=obj.member_mobile).exists()):
                        return Response({"error_detail": ["Mobile Number already in use."]}, status=status.HTTP_400_BAD_REQUEST)
                    if (Member.objects.filter(aadhar_no=obj.aadhar_no).exists()):
                        return Response({"error_detail": ["Aadhar Number already in use."]}, status=status.HTTP_400_BAD_REQUEST)
                    # CHECK UNIQUE ?   ->  # check aadhar no,firm_name,firm_contact_number,firm vat_no,firm_tin_no,firm_pan_no,gst_no,

                    # Check if username already exists and make a new username
                    while User.objects.filter(username=username).exists():
                        username += str(randint(1, 99))
                    # plain_passwd = ''.join(choices(
                    #     string.ascii_lowercase + string.digits, k=8))
                    # print(obj.aadhar_no[8:], (obj.member_mobile)[6:])
                    plain_passwd = obj.aadhar_no[8:] + obj.member_email.split(
                        '@')[0] + (obj.member_mobile)[6:]
                    # print('pass===>', plain_passwd)
                    passwd = make_password(plain_passwd)
                    user = User.objects.create(username=username,
                                               is_customer=1, email=obj.member_email, password=passwd)
                    # add to member
                    data = model_to_dict(obj)
                    data['user'] = user
                    data['firm_district_id'] = data['firm_district']
                    data['membership_type_id'] = data['membership_type']
                    del data['firm_district']
                    del data['membership_type']
                    del data['id_membership_req']
                    del data['membership_is_approved']
                    del data['member_email']
                    member = Member.objects.create(**data)

                    # delete membership object
                    obj.delete()

                    # send_mail
                    # password is last 4 digits of adhar and last 4 digits of mobile number

                    html_message = render_to_string('member_account_creation.html', {
                        "name": member.full_name, "username": user.username})
                    send_mail(subject='Membership Request Accepted', message='Welcome .. pass is {}'.format(plain_passwd),
                              html_message=html_message,
                              from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[user.email])
                    return Response({"message": "Member Accepted, Member account created"}, status=status.HTTP_200_OK)

            # Rejecting Membership
            if 'reject_membership' in request.data:
                # if 'reject_reason' in request.data:
                if request.data.get('reject_membership'):
                    obj = self.get_object()
                    # if no protection delete directly
                    obj.member_photo.delete()
                    obj.aadhar_image.delete()
                    obj.firm_vat_image.delete()
                    obj.firm_tin_image.delete()
                    obj.firm_pan_image.delete()
                    obj.trade_license_image.delete()
                    obj.visiting_card_image.delete()
                    obj.resolution_image.delete()
                    obj.delete()

                    # if any(
                    #     filter_.exists() for filter_ in [
                    #         User.objects.filter(Q(email=obj.member_email) | Q(
                    #             member__member_mobile=obj.member_mobile)),
                    #         Member.objects.filter(aadhar_no=obj.aadhar_no)
                    #     ]
                    # ):
                    #     pass

                    if any(
                        filter_.exists() for filter_ in [
                            User.objects.filter(email=obj.member_email),
                            Member.objects.filter(
                                member_mobile=obj.member_mobile),
                            Member.objects.filter(aadhar_no=obj.aadhar_no)
                        ]
                    ):
                        pass

                    else:
                        html_message = render_to_string('member_rejection_template.html', {
                            "name": obj.full_name})
                        send_mail(subject='Membership Request Rejected', message='Your Membership request is rejected',
                                  html_message=html_message,
                                  from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[obj.member_email])
                #
                return Response({"success": True, "message": "Membership request rejected"}, status=status.HTTP_200_OK)
                # return Response({"error_detail": ["Please provide rejection reason."]}, status=status.HTTP_400_BAD_REQUEST)
            return Response(status=status.HTTP_200_OK)
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    # def delete(self, request, *args, **kwargs):
    #     # delete instance
    #     if 'pk' in kwargs:
    #         obj = self.get_object()
    #         try:
    #             if (hasattr(obj, 'customer')):
    #                 raise ProtectedError(
    #                     'Cannot delete. Membership details are in use', obj)
    #             obj.member_photo.delete()
    #             obj.aadhar_image.delete()
    #             obj.firm_vat_image.delete()
    #             obj.firm_tin_image.delete()
    #             obj.firm_pan_image.delete()
    #             obj.trade_license_image.delete()
    #             obj.visiting_card_image.delete()
    #             obj.resolution_image.delete()
    #             obj.delete()
    #         except ProtectedError:
    #             return Response({"error_detail": ["Cannot delete. Membership details are in use"]}, status=status.HTTP_400_BAD_REQUEST)
    #         return Response(status=status.HTTP_204_NO_CONTENT)
    #     return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)


class MemberSubscriptionView(generics.GenericAPIView):
    permission_classes = [isAdmin]
    queryset = Member.objects.all()

    def get(self, request, *args, **kwargs):
        if 'pk' in kwargs:
            member = self.get_object()
            membership = {"member_id": member.pk, 'member_name': member.full_name, "firm_name": member.firm_name,
                          "membership_active": member.check_is_active(),
                          "membership_start_date": member.membership_start_date,
                          "membership_expiry_date": member.membership_expiry_date,
                          "membership_type": {"id": member.membership_type.id, "name": member.membership_type.name,
                                              "price": member.membership_type.price,
                                              "duration_months": member.membership_type.duration_months},
                          }
            return Response(membership)
        members = self.get_queryset()
        output = [{"member_id": member.pk, 'member_name': member.full_name, "firm_name": member.firm_name,
                   "membership_active": member.check_is_active(),
                   "membership_start_date": member.membership_start_date,
                   "membership_expiry_date": member.membership_expiry_date,
                   } for member in members]
        return Response(sorted(output, key=lambda k: (k['membership_expiry_date'] is not None, k['membership_expiry_date']), reverse=True))

    def put(self, request, *args, **kwargs):
        if 'pk' in kwargs:
            if 'renew_subscription' and 'membership_type' in request.data:
                member = self.get_object()
                member.membership_type_id = request.data['membership_type']
                new_expiry = MembershipType.objects.get(id=request.data['membership_type']).get_expiry_date(
                    member.membership_expiry_date)
                if member.membership_start_date == None:
                    member.membership_start_date = timezone.now().date()
                member.membership_expiry_date = new_expiry
                member.save()
                return Response({"success": True, "message": "Membership Renewed"})
            if 'end_subscription' in request.data:
                member = self.get_object()
                member.membership_start_date = None
                member.membership_expiry_date = None
                member.save()
                return Response({"success": True, "message": "Membership Ended"})
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)


# Get Membership Types
class MembershipTypesAdminView(generics.GenericAPIView):
    permission_classes = [isAdmin]

    def get(self, request, *args, **kwargs):
        return Response(MembershipType.objects.all().values())

class ActiveSubscription(generics.GenericAPIView):
    permission_classes = [isAdmin]
    queryset = Member.active_members.count()

    def get(self, request, *args, **kwargs):
        members = Member.active_members.count()
        output = members
        return Response(output)
    
class ActiveMembers(generics.GenericAPIView):
    permission_classes = [isAdmin]
    queryset = Member.active_members.all().order_by('-membership_start_date')

    def get(self, request, *args, **kwargs):
        members = self.get_queryset()
        output = [{"member_id": member.pk, 'member_name': member.full_name, "firm_name": member.firm_name,
                   "membership_active": member.check_is_active(),
                   "membership_start_date": member.membership_start_date,
                   "membership_expiry_date": member.membership_expiry_date,
                   } for member in members]
        return Response(sorted(output, key=lambda k: (k['membership_expiry_date'] is not None, k['membership_expiry_date'])))
    
class TotalSubscription(generics.GenericAPIView):
    permission_classes = [isAdmin]
    queryset = Member.objects.count()

    def get(self, request, *args, **kwargs):
        members = Member.objects.count()
        output = members
        return Response(output)

class NewUsers(generics.ListAPIView):
    permission_classes = [isAdmin]
    queryset = Member.objects.all().order_by('-member_id')

    def get(self, request, *args, **kwargs):
        members = self.get_queryset()
        output = [{"member_id": member.pk, 'member_name': member.full_name, "firm_name": member.firm_name,
                   "membership_active": member.check_is_active(),
                   "membership_start_date": member.membership_start_date,
                   "membership_expiry_date": member.membership_expiry_date,
                  
                   } for member in members]
        return Response(output)
    
class YettoExpire(generics.ListAPIView):
    permission_classes = [isAdmin]
    queryset = Member.active_members.all().order_by('-membership_expiry_date')

    def get(self, request, *args, **kwargs):
        members = self.get_queryset()
        output = [{"member_id": member.pk, 'member_name': member.full_name, "firm_name": member.firm_name,
                   "membership_active": member.check_is_active(),
                   "membership_start_date": member.membership_start_date,
                   "membership_expiry_date": member.membership_expiry_date,
                   } for member in members]
        return Response(sorted(output, key=lambda k: (k['membership_expiry_date'] is not None, k['membership_expiry_date']), reverse=False))