import os


# function for storing Member personal image in specified media path with file naming in specific pattern
def member_personal_image(instance, filename):
    _, file_extension = os.path.splitext(filename)
    return 'images/membership/personal/{name}_{firm}{ext}'.format(name=instance.full_name, firm=instance.firm_name, ext=file_extension)


# function for storing Member aadhar image in specified media path with file naming in specific pattern
def member_aadhar_image(instance, filename):
    _, file_extension = os.path.splitext(filename)
    return 'images/membership/aadhar/{name}_{firm}{ext}'.format(name=instance.full_name, firm=instance.firm_name, ext=file_extension)


# function for storing Member firm_vat image in specified media path with file naming in specific pattern
def firm_vat_image(instance, filename):
    _, file_extension = os.path.splitext(filename)
    return 'images/membership/firm_vat/{name}_{firm}{ext}'.format(name=instance.full_name, firm=instance.firm_name, ext=file_extension)


# function for storing Member firm_tin image in specified media path with file naming in specific pattern
def firm_tin_image(instance, filename):
    _, file_extension = os.path.splitext(filename)
    return 'images/membership/firm_tin/{name}_{firm}{ext}'.format(name=instance.full_name, firm=instance.firm_name, ext=file_extension)


# function for storing Member firm_pan image in specified media path with file naming in specific pattern
def firm_pan_image(instance, filename):
    _, file_extension = os.path.splitext(filename)
    return 'images/membership/firm_pan/{name}_{firm}{ext}'.format(name=instance.full_name, firm=instance.firm_name, ext=file_extension)


# function for storing Member trade_license image in specified media path with file naming in specific pattern
def trade_license_image(instance, filename):
    _, file_extension = os.path.splitext(filename)
    return 'images/membership/trade_license/{name}_{firm}{ext}'.format(name=instance.full_name, firm=instance.firm_name, ext=file_extension)


# function for storing Member visiting_card image in specified media path with file naming in specific pattern
def visiting_card_image(instance, filename):
    _, file_extension = os.path.splitext(filename)
    return 'images/membership/visiting_card/{name}_{firm}{ext}'.format(name=instance.full_name, firm=instance.firm_name, ext=file_extension)


# function for storing Member resolution image in specified media path with file naming in specific pattern
def resolution_image(instance, filename):
    _, file_extension = os.path.splitext(filename)
    return 'images/membership/resolution/{name}_{firm}{ext}'.format(name=instance.full_name, firm=instance.firm_name, ext=file_extension)
