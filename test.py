'''

a script to add random 5 users to the database at an interval of 5 minutes
class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[InputRequired()])
    last_name = StringField('Last Name', validators=[InputRequired()])
    username = StringField('Username', validators=[InputRequired()])
    email = StringField('Email', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    sub_family = SelectField('Sub Family', choices=[
        ('', 'Select your sub-family'),
        ('Pauline Nduta', 'Pauline Nduta'),
        ('Jane Njeri', 'Jane Njeri'),
        ('Catherine Wairimu', 'Catherine Wairimu'),
        ('Geoffrey Kaboro', 'Geoffrey Kaboro'),
        ('Loise Ruguru', 'Loise Ruguru'),
        ('Simon Kioi', 'Simon Kioi')
    ], validators=[InputRequired()])



'''
import requests
import random
import time
from datetime import datetime
from faker import Faker
from faker.providers import internet
from faker.providers import person
from faker.providers import address
from faker.providers import company
from faker.providers import job
from faker.providers import phone_number
from faker.providers import lorem
from faker.providers import date_time
from faker.providers import misc
from faker.providers import profile
from faker.providers import python


fake = Faker()
fake.add_provider(internet)
fake.add_provider(person)
fake.add_provider(address)
fake.add_provider(company)
fake.add_provider(job)
fake.add_provider(phone_number)
fake.add_provider(lorem)
fake.add_provider(date_time)
fake.add_provider(misc)


def generate_random_user():
    first_name = fake.first_name()
    last_name = fake.last_name()
    username = first_name + last_name
    email = fake.email()
    password = fake.password()
    sub_family = random.choice(['Pauline Nduta', 'Jane Njeri', 'Catherine Wairimu', 'Geoffrey Kaboro', 'Loise Ruguru', 'Simon Kioi'])
    return {
        'first_name': first_name,
        'last_name': last_name,
        'username': username,
        'email': email,
        'password': password,
        'sub_family': sub_family
    }

