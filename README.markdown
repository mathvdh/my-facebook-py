This a little file that I have used for all my facebook projects, It has been used and ameliored in the last months. It was made to work with the Django Web framework.

A big part of this file is from the original python sdk by Facebook and you can find more informations here : https://github.com/facebook/python-sdk/

Also if your doing facebook applications a good source of documentation is the official facebook documentation here : http://developers.facebook.com

#### How to use it.
First you need to import it where you want to use it : `from facebook.py import *`

Then you specify all your facebook settings in your django settings file like this :
    `FACEBOOK_APP_ID = "YOUR_APP_ID_HERE"
    FACEBOOK_APP_SECRET = "YOUR_APP_SECRET_HERE"
    FACEBOOK_REQ_PERMS = ("permission1","permission2","permission3")
    CANVAS_URI = "YOUR_CANVAS_URL_FOR_REDIRECTION_AFTER_AUTH"`

Then either you create your facebook object and use it directly like this :
    `fb = Facebook()`

Or if you dont want to use the django settings systems you can specify all this options when you create your FB object :
    `fb = Facebook(FACEBOOK_APP_ID,FACEBOOK_APP_SECRET,FACEBOOK_REQ_PERMS,CANVAS_URI)`

After that you can start using your facebook object for different uses, for example if you want to authenticate your user to facebook and ask for the permissions in FACEBOOK_REQ_PERMS
You could just do this :
    `fb.build_authentication_redirect()`

That will build an HttpResponse for you that will redirect the user to facebook oauth for authentification and permissions granting. After that ther user will be redirected to CANVAS_URI.
And you can start using it for real like :
    `fb.put_wall_post("hello")`
That will post somethig on user's wall, or :
    `fb.get_object("me")`
That will return the graph api content for the connected user.

#### View decorators.
Another (easier) way to handle all the authentication and redirection stuff is to used the given view decorators :
`@fbsig_required` and `@fbsig_redirect`

The first one will check if the user is authenticated against facebook and display an error if not and your view if yes.
The second one will check if the user is authenticated, if not it will redirect the user for auth and permissions and then redirect to CANVAS_URI.

Example :

    @fbsig_redirect
    def my_super_view(request,chat_session_id):
        if request.fbObject is not None:
            me = request.fbObject.get_object("me")
            #do something with "me"

            return render_to_response('my_super_template.html',{
            "user_fbid":request.fbObject.user_id,
            "fbapp_id":settings.FACEBOOK_APP_ID,
            "signed_request":request.fbObject.coded_signed_request
            },context_instance=RequestContext(request))


What those view decorators do, is that they check if the "signed_request" POST parameter is attached to the request (it is added by facebook when it displays your canvas in an iframe).
If yes it builds a Facebook() object from it and attach it to the request as request.fbObject.

If not it either redirects the user for auth or display an error depending on which view decorator you want.
    
    