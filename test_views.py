from unittest.mock import PropertyMock, patch
import pytest
from django.urls import reverse
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm
from django.test import Client
from accounts.models import recruiter, jobseeker
from jobseeker.models import resume
from django.core import mail

# Fixture to create a user for testing login and registration functionality.
@pytest.fixture
def user(db):
    user = User.objects.create_user(username='testuser', email='user@example.com')
    user.set_password('securepassword123')
    user.is_active = True
    user.save()
    return user

# Test registration view with valid data
@pytest.mark.django_db
def test_register_view_valid(client):
    """
    Test the registration view with valid user data to ensure it correctly registers the user
    and redirects to the correct page.
    """
    url = reverse('accounts:register')
    data = {
        'username': 'newuser',
        'email': 'newuser@example.com',
        'password1': 'ComplexPass123!',
        'password2': 'ComplexPass123!',
        'fname': 'Test',
        'lname': 'User',
        'user_type': 'jobseeker'
    }
    response = client.post(url, data)
    assert response.status_code == 302
    assert User.objects.filter(username='newuser').exists()

# Test registration with an already existing email
@pytest.mark.django_db
def test_register_view_existing_email(client):
    """
    Test the registration view with an existing email to ensure it handles duplicate emails
    properly and does not register a new user.
    """
    existing_user = User.objects.create_user(username='existinguser', email='existing@example.com', password='password123')
    url = reverse('accounts:register')
    data = {
        'username': 'newuser',
        'email': 'existing@example.com',
        'password1': 'ComplexPass123!',
        'password2': 'ComplexPass123!',
        'fname': 'Test',
        'lname': 'User',
        'user_type': 'jobseeker'
    }
    response = client.post(url, data)
    assert 'This email is already associated with another account.' in response.content.decode('utf-8')
    assert response.status_code == 200
    assert User.objects.filter(username='newuser').count() == 0

@pytest.mark.django_db
def test_register_with_short_password(client):
    """
    Test registration with a password that is too short to ensure that validation catches the error.
    """
    url = reverse('accounts:register')  # Update with the correct URL name if different
    registration_data = {
        'username': 'newuser',
        'email': 'newuser@example.com',
        'password1': 'short',  # Deliberately too short
        'password2': 'short',  # Must match password1
        'fname': 'Test',       # Assuming these are required fields
        'lname': 'User'
    }
    response = client.post(url, registration_data)
    assert response.status_code == 200  # Page should reload with form errors

    # Check for the presence of a password too short error
    # The specific error message might vary based on your Django version and settings
    assert 'This password is too short. It must contain at least 8 characters.' in response.content.decode()

@pytest.mark.django_db
def test_register_with_duplicate_username(client):
    """
    Test registration with a duplicate username to ensure that the form rejects this with an appropriate error message.
    """
    username = "testuser"
    # Create an initial user with the username
    User.objects.create_user(username=username, email="user@example.com", password="testpassword123")

    url = reverse('accounts:register')  # Update with the correct URL name if different
    registration_data = {
        'username': username,  # Using the same username as the initially created user
        'email': 'newuser@example.com',
        'password1': 'ValidPass123!',  # Use a valid password to isolate the test case to the username
        'password2': 'ValidPass123!',
        'fname': 'Test',       # Assuming these are required fields based on your form
        'lname': 'User'
    }
    response = client.post(url, registration_data)
    assert response.status_code == 200  # Expecting the form to reload with errors

    # Check for the presence of a duplicate username error message
    assert 'A user with that username already exists.' in response.content.decode()
# Test login functionality with correct credentials
@pytest.mark.django_db
def test_login_view_correct_credentials(client, user):
    """
    Test that the user can log in with correct credentials and that the session is
    correctly initiated.
    """
    url = reverse('accounts:login')
    data = {'username': 'testuser', 'password': 'securepassword123'}
    response = client.post(url, data, follow=True)
    assert response.status_code == 200
    assert response.context['user'].is_authenticated

# Test login with incorrect password
@pytest.mark.django_db
def test_login_view_incorrect_password(client, user):
    """
    Test login functionality with an incorrect password to ensure it does not authenticate
    and shows appropriate error messages.
    """
    url = reverse('accounts:login')
    data = {'username': 'testuser', 'password': 'wrongpassword'}
    response = client.post(url, data)
    assert 'Please enter a correct username and password.' in response.content.decode('utf-8')
    assert response.status_code == 200
    assert not response.context['user'].is_authenticated

# Test accessing a view that requires authentication without being logged in
@pytest.mark.django_db
def test_jobseeker_index_access_denied(client):
    """
    Ensure that the jobseeker index page requires user authentication, and redirects
    unauthenticated users to the login page.
    """
    url = reverse('accounts:jobseeker_index')
    response = client.get(url)
    assert response.status_code == 302
    assert 'login' in response.url

@pytest.fixture
def recruiter_user(user, db):
    """Create a jobseeker linked to the user."""
    return recruiter.objects.create(user=user)

@pytest.mark.django_db
def test_recruiter_index_authenticated_access(client, recruiter_user):
    """
    Ensure that an authenticated recruiter can access the recruiter_index page.
    """
    client.force_login(recruiter_user.user)
    url = reverse('accounts:recruiter_index')
    response = client.get(url)
    assert response.status_code == 200

@pytest.mark.django_db
def test_reset_password_request_valid_email(client, user):
    """
    Test sending a password reset request with a valid email and check for the expected
    success message or redirection.
    """
    url = reverse('accounts:reset_request')
    data = {'email': user.email}
    response = client.post(url, data)
    assert response.status_code == 302  # Assuming there is a redirect after successful submission
    assert len(mail.outbox) == 1  # Check that one message has been sent
    assert f'http://testserver/reset_password/?user_id={user.id}' in mail.outbox[0].body.lower()  # Adjust the message to what you expect


@pytest.mark.django_db
def test_reset_password_request_invalid_email(client):
    """
    Test sending a password reset request with an invalid email.
    """
    url = reverse('accounts:reset_request')
    data = {'email': 'nonexistent@example.com'}
    response = client.post(url, data)
    assert response.status_code == 200
    assert 'no user found with that email address' in response.content.decode('utf-8').lower()

def test_resume_locked(client, jobseeker):
    """
    Ensure that the resume is locked when 'lock' is included in the POST data.
    """
    client.force_login(jobseeker.user)
    url = reverse('save_resume')  # Make sure this URL is correct for the save_resume view
    session = client.session
    session['user_data'] = {'resumeid': -1}  # Assuming new resume creation
    session.save()

    response = client.post(url, {
        'resumeName': 'My New Resume',
        'lock': 'on',  # Simulating the checkbox for locking the resume
    })

    # Fetch the latest resume for the jobseeker and check the lock status
    created_resume = resume.objects.filter(user=jobseeker).latest('id')
    assert created_resume.lock is True

@pytest.fixture
def jobseeker_user(user, db):
    """Create a jobseeker linked to the user."""
    return jobseeker.objects.create(user=user)

@pytest.mark.django_db
def test_resume_locked(client, jobseeker_user):
    client.force_login(jobseeker_user.user)
    url = reverse('jobseeker:save_resume')
    session = client.session
    session['user_data'] = {'resumeid': -1}
    session.save()

    response = client.post(url, {
        'resumeName': 'My New Resume',
        'lock': 'on',
    })

    created_resume = resume.objects.filter(user=jobseeker_user).latest('id')
    assert created_resume.lock is True

@pytest.mark.django_db
def test_resume_unlocked(client, jobseeker_user):
    client.force_login(jobseeker_user.user)
    url = reverse('jobseeker:save_resume')
    session = client.session
    session['user_data'] = {'resumeid': -1}
    session.save()

    response = client.post(url, {
        'resumeName': 'My New Resume'
    })

    created_resume = resume.objects.filter(user=jobseeker_user).latest('id')
    assert created_resume.lock is False

@pytest.mark.django_db
def test_bookmark_resume(client, jobseeker_user, recruiter_user):
    client.force_login(jobseeker_user.user)
    url = reverse('jobseeker:save_resume')
    session = client.session
    session['user_data'] = {'resumeid': -1}
    session.save()
    client.post(url, {
        'resumeName': 'My New Resume'
    })
    created_resume = resume.objects.filter(user=jobseeker_user).latest('id')
    client.force_login(recruiter_user.user)
    url = reverse('recruiter:bookmark_resume', args=[created_resume.id])
    response = client.get(url)
    assert response.json() == {'status': 'success', 'message': 'Bookmark created successfully'}
    assert created_resume.lock is False

@pytest.mark.django_db
def test_unbookmark_resume(client, jobseeker_user, recruiter_user):
    client.force_login(jobseeker_user.user)
    url = reverse('jobseeker:save_resume')
    session = client.session
    session['user_data'] = {'resumeid': -1}
    session.save()
    client.post(url, {
        'resumeName': 'My New Resume'
    })
    created_resume = resume.objects.filter(user=jobseeker_user).latest('id')
    client.force_login(recruiter_user.user)
    url = reverse('recruiter:bookmark_resume', args=[created_resume.id])
    client.get(url)
    url = reverse('recruiter:unbookmark_resume', args=[created_resume.id])
    response = client.get(url)
    assert created_resume.lock is False
    assert response.json() == {'status': 'success'}
    

