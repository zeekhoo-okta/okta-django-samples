# Okta OpenID Connect/OAuth2 Sample in Django

This sample provides an example of using Okta to login to a Django application. 
We use the [Okta Sign-In Widget](http://developer.okta.com/code/javascript/okta_sign-in_widget) to quickly add an Okta login interface to the Django app.

Architecturally, Okta acts as an Identity Provider external to Django and integrates using OpenID Connect: 
The user is authenticated by Okta, which sends OpenID Connect id_token (and optionally access_token) to a callback controller that will validate the token(s). 
Upon successful validation, login the user (if existing) else Just-in-time "JIT" provision the Django user. This end-to-end process is akin to Okta doing a Single-Sign-On into Django.

For completeness, we stack the @login_required decorator with a custom @okta_login_required decorator, which checks if JWT token(s) were successfully retrieved from Okta. 
Additional custom validations (e.g. checking for certain claims - such as role information - in the token(s)) would/cloud be placed in the custom decorator as well.

### This project is written in Python 3.6 and Django 2

## Running the Sample

### Pre-requisites
If you do not have an Okta account, please [sign up here](https://www.okta.com/developer/signup/).

#### Basic setup:
*You may tweak settings later as you gain more familiarity with the Okta platform. For starting out however, simply follow these instructions closely*
1. Under the **Applications** menu, click **Add Application** and select **Web**
2. Click **Next**, then enter an Application **Name**. Then:
   * Set Base URIs to `http://localhost:8000/`
   * Add `http://localhost:8000/oauth2/callback/` the list of *Login Redirect URIs*
   * Add `http://localhost:8000` to the list of *Logout Redirect URIs*  
   * Leave the default setting, Group assignments = **Everyone**
3. Click **Done** to redirect back to the *General* tab of your application.
4. Make note of the **Client ID** and **Client Secret**, as it will be needed environment configuration
5. Navigate to the **Dashboard** menu of your *Developer Console*. Make note of the **Org URL** value found on the top right-hand corner of the screen
6. Edit the **.env** file included in this sample:
   - Provide the value for ORG_URL from step 5 above
   - Provide the value for ISSUER, by concatenating "/oauth2/default" to the ORG_URL value
   - Provide values for CLIENT_ID and CLIENT_SECRET, both obtained in step 4 above
   - Leave the values for SCOPES and REDIRECT_URI as-is
7. Enable [CORS access](https://developer.okta.com/docs/api/getting_started/enabling_cors) to your Okta org
   - In the navigation menu, select **API** then **Trusted Origins**
   - Click **Add Origin**
   - Set **Origin URL** = `http://localhost:8000` and check the box **CORS**
   - Save

### Build Instructions
Use the following commands on Mac OS X or Linux:
```
    $ python3 -m venv venv
    $ source venv/bin/activate
    $ pip install -r requirements.txt
```
Run migrations (In this sample we're simply using sqlite); Tables are needed for session management.
```
    $ python manage.py migrate
```

### Run the Sample
Source the environment variables (**.env** file)
```
    $ source .env
```

Start the web server with `python manage.py runserver`
```
    $ python manage.py runserver
```

Navigate to `http://localhost:8000` to login using the [Okta Sign-In Widget](http://developer.okta.com/code/javascript/okta_sign-in_widget)
