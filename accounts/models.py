from django.utils import timezone
from django.db import models
from django.contrib.auth.models import AbstractUser
from . import file_save
from dateutil.relativedelta import relativedelta


# Accounts , access related models
# User model is used to store Users ; to be used as basic auth model for authentication of both admin and customers
class User(AbstractUser):
    is_customer = models.BooleanField(default=False)
    is_adminuser = models.BooleanField(default=False)
    account_expiry = models.DateField(blank=True, null=True)
    first_name = models.CharField(max_length=45, null=True, blank=True)
    last_name = models.CharField(max_length=45, null=True, blank=True)
    email = models.EmailField(unique=True)

    def __str__(self) -> str:
        return 'User - ' + str(self.pk)

    LOGGING_IGNORE_FIELDS = ('password', 'first_name',
                             'last_name', 'last_login')

    class Meta:
        db_table = 'users'
        constraints = [
            models.CheckConstraint(violation_error_message='isAdmin and isCustomer values cannot be same', name='Admin and Customer values cannot be same', check=~(
                models.Q)(is_customer=models.F('is_adminuser'))),
            models.CheckConstraint(violation_error_message='Customer cannot become a staff',
                                   name='Customer cannot become a staff', check=~models.Q(models.Q(is_customer=True), models.Q(is_staff=True))),
            models.CheckConstraint(violation_error_message='Customer cannot become superuser',
                                   name='Customer cannot become superuser', check=~models.Q(models.Q(is_customer=True), models.Q(is_superuser=True))),
            models.CheckConstraint(
                check=models.Q(
                    username__regex=r'^\w(?:\w|[.-](?=\w))*$'
                ),
                name="Invalid username",
                violation_error_message="Username must only contain alphanumeric characters, '@', '#', '-', '_', and '.'",
            )
        ]


# Admin model is used to store Admin users
class Admin(models.Model):
    adminid = models.AutoField(primary_key=True)
    name = models.CharField(
        max_length=100)
    user = models.OneToOneField(
        'User', on_delete=models.PROTECT, limit_choices_to={'is_adminuser': True}, related_name='admin')
    admin_email_verified = models.BooleanField(default=False)

    def __str__(self) -> str:
        return 'Admin User - ' + str(self.pk)

    class Meta:
        db_table = 'admin'


# Admin OTP model is used to store Email OTPs of user
class AdminOTP(models.Model):

    OTP_FOR = (
        ("0", "Password Reset OTP"),
        ("1", "Profile Email Change OTP"),
        ("2", "Email Verify OTP"),
    )

    id_otp = models.BigAutoField(primary_key=True)
    admin = models.ForeignKey(
        'Admin', on_delete=models.CASCADE, related_name='otp_set')
    email_id = models.EmailField()
    otp_code = models.CharField(
        max_length=6)
    creation_time = models.DateTimeField(default=timezone.now)
    expiry = models.DateTimeField()
    otp_for = models.CharField(choices=OTP_FOR, max_length=1)

    def __str__(self) -> str:
        return 'Admin User OTP - ' + str(self.pk)

    class Meta:
        db_table = 'admin_otp'
    # LOG IGNORE THIS MODEL


# Membership Type model
class MembershipType(models.Model):
    name = models.CharField(max_length=50)
    description = models.CharField(max_length=200, blank=True, null=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    duration_months = models.PositiveIntegerField(unique=True, error_messages={
                                                  'unique': "Membership Type with this duration already exists"})

    def __str__(self):
        return self.name

    def get_expiry_date(self, start_date):
        if start_date == None:
            return timezone.now().date() + relativedelta(months=self.duration_months)
        return start_date + relativedelta(months=self.duration_months)

    class Meta:
        db_table = 'membership_type'


# Membership Base model - which contains neccessary common fields
class MembershipBaseModel(models.Model):
    full_name = models.CharField(max_length=75, default=None)
    member_photo = models.ImageField(upload_to=file_save.member_personal_image)
    aadhar_no = models.CharField(max_length=12, default=None)
    aadhar_image = models.ImageField(upload_to=file_save.member_aadhar_image)
    member_mobile = models.CharField(max_length=10)
    firm_name = models.CharField(max_length=100, default=None)
    firm_district = models.ForeignKey(
        'District', on_delete=models.PROTECT)
    firm_contact_number = models.CharField(
        max_length=20, default=None, blank=True, null=True)
    firm_address = models.TextField()
    firm_vat_no = models.CharField(
        max_length=20, default=None, blank=True, null=True)
    firm_vat_image = models.ImageField(
        upload_to=file_save.firm_vat_image, default=None)
    firm_tin_no = models.CharField(
        max_length=20, default=None, blank=True, null=True)
    firm_tin_image = models.ImageField(
        upload_to=file_save.firm_tin_image, default=None)
    firm_pan_no = models.CharField(
        max_length=20, default=None, blank=True, null=True)
    firm_pan_image = models.ImageField(
        upload_to=file_save.firm_pan_image, default=None)
    gst_number = models.CharField(
        max_length=20, default=None, blank=True, null=True)
    trade_license_image = models.ImageField(
        upload_to=file_save.trade_license_image)
    visiting_card_image = models.ImageField(
        upload_to=file_save.visiting_card_image, default=None)
    resolution_image = models.ImageField(
        upload_to=file_save.resolution_image, default=None)
    membership_type = models.ForeignKey(
        'MembershipType', on_delete=models.PROTECT)

    class Meta:
        abstract = True


# Member model is used to store Association Approved Member details and has provision to login
class Member(MembershipBaseModel):
    member_id = models.AutoField(primary_key=True)
    member_mobile = models.CharField(
        max_length=10, unique=True, default=None,  error_messages={
            "unique": "Mobile Number already in use"})
    user = models.OneToOneField(
        'User', on_delete=models.PROTECT, limit_choices_to={'is_customer': True}, related_name='customer')
    member_email_verified = models.BooleanField(default=False)
    member_mobile_verified = models.BooleanField(default=False)
    aadhar_no = models.CharField(max_length=18, default=None, unique=True, error_messages={
        "unique": "Aadhar number already in use"})
    membership_start_date = models.DateField(default=None, null=True)
    membership_expiry_date = models.DateField(default=None, null=True)

    def __str__(self) -> str:
        return 'Member - ' + str(self.pk)

    def check_is_active(self) -> bool:
        if self.membership_expiry_date == None or self.membership_start_date == None:
            return False
        return self.membership_expiry_date >= self.membership_start_date and self.membership_expiry_date >= timezone.now().date()

    class Meta:
        db_table = 'member'


# Member OTP model is used to store Email OTPs of members
class MemberOTP(models.Model):

    OTP_FOR = (
        ("0", "Password Reset OTP"),
        # ("1", "Profile Email Change OTP"),
        # ("2", "Email Verify OTP"),
    )

    id_otp = models.BigAutoField(primary_key=True)
    member = models.ForeignKey(
        'Member', on_delete=models.CASCADE, related_name='otp_set')
    email_id = models.EmailField()
    otp_code = models.CharField(
        max_length=6)
    creation_time = models.DateTimeField(default=timezone.now)
    expiry = models.DateTimeField()
    otp_for = models.CharField(choices=OTP_FOR, max_length=1)

    def __str__(self) -> str:
        return 'Member OTP - ' + str(self.pk)

    class Meta:
        db_table = 'member_otp'


# Membership  - Model to store Membership requests/details , which is need to approved by admin
class MembershipRequest(MembershipBaseModel):
    id_membership_req = models.AutoField(primary_key=True)
    membership_is_approved = models.BooleanField(
        default=False)  # add editabe --> False
    member_email = models.EmailField()

    def __str__(self) -> str:
        return 'Membership Request - ' + str(self.pk)

    class Meta:
        db_table = 'membership'


# Country model is used to store country
class Country(models.Model):
    id_country = models.AutoField(primary_key=True)
    country_name = models.CharField(max_length=255)

    def __str__(self) -> str:
        return 'Country - ' + str(self.pk)

    class Meta:
        db_table = 'country'


# State model is used to store the states of corresponding country
class State(models.Model):
    id_state = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    country = models.ForeignKey(
        'Country', on_delete=models.PROTECT, related_name='states')

    def __str__(self) -> str:
        return 'State - ' + str(self.pk)

    class Meta:
        db_table = 'state'


# District model is used to store the districts of corresponding states
class District(models.Model):
    id_district = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    state = models.ForeignKey(
        'State', on_delete=models.PROTECT, related_name='districts')

    def __str__(self) -> str:
        return 'District - ' + str(self.pk)

    class Meta:
        db_table = 'district'


# Settings model is used to store some global settings
class Settings(models.Model):
    id_settings = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    value = models.CharField(max_length=255)

    def __str__(self) -> str:
        return 'Settings - ' + str(self.pk)

    class Meta:
        db_table = 'settings'


# menu model is used to store the admin menu - side menus
class AdminMenu(models.Model):
    text = models.CharField(max_length=45)
    link = models.CharField(max_length=75,  unique=True, error_messages={
                            "unique": "Menu with this link already exists"})
    icon = models.CharField(max_length=85, null=True, blank=True)
    parent = models.ForeignKey(
        'AdminMenu', null=True, blank=True, default=None, on_delete=models.SET_NULL)
    order = models.IntegerField(default=0)
    active = models.BooleanField(default=True)
    title = models.CharField(max_length=125, null=True)

    def __str__(self) -> str:
        return 'Admin Menu - ' + str(self.pk)

    class Meta:
        db_table = "admin_menu"


# Admin menu access model is used to store the permissions of admin on individual menu items - Admin side menu
class AdminMenuAccess(models.Model):
    id_admin_menu_access = models.AutoField(primary_key=True)
    admin = models.ForeignKey('Admin',
                              on_delete=models.CASCADE,
                              related_name="menu_access")
    menu = models.ForeignKey('AdminMenu',
                             on_delete=models.CASCADE,
                             related_name="access_admin")
    view = models.BooleanField(default=False)
    add = models.BooleanField(default=False)
    edit = models.BooleanField(default=False)
    delete = models.BooleanField(default=False)

    def __str__(self) -> str:
        return 'Admin Menu Access - ' + str(self.pk)

    class Meta:
        db_table = "admin_menu_access"
