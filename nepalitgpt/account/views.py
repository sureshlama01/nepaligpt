from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from account.models import User
from account.serializers import UserSerializer,UserLoginSerializer,UserProfileSerializer,changePasswordSerializer,EmailSerialzier,PasswordResetSerializer
from django.contrib.auth import authenticate
from account.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated,AllowAny
from rest_framework.viewsets import ModelViewSet
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.urls import reverse
from django.utils import timezone  # Import timezone module
from django.core.mail import send_mail
from djangoauth import settings

# Create Mannually Token
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]
    def post(self,request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = get_tokens_for_user(user)
            headers = self.get_success_headers(serializer.data)
            return Response({'token':token,'message':'User registration successfull'},status=status.HTTP_201_CREATED,headers=headers)
        else:
            return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
            
class UserLoginView(APIView):
    renderer_classes = [UserRenderer]
    def post(self,request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data['email']
            password = serializer.data['password']
            user = authenticate(email=email,password=password)
            if user is not None:
                token = get_tokens_for_user(user)
                return Response({'token':token,"message": "User login successfully"},status=status.HTTP_200_OK)
            else:
                return Response({"error":{"non_field_errors":['Email or Password invalid!']}},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get (self,request):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data,status=status.HTTP_200_OK)
    
    
# Password Change View
class ChangePasswordView(ModelViewSet):
    """
    An endpoint for changing password.
    """
    serializer_class = changePasswordSerializer
    model = User
    permission_classes = [IsAuthenticated]

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        self.object = self.get_object()
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(old_password):
                return Response({'error': 'Old password does not match'}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(new_password)
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }
            mail_subject = "Your Password Has Been Changed Successfully"
            message = f'''
Dear {self.request.user.name},

We wanted to let you know that your password was successfully changed. If you made this change, no further action is needed.

Account Details:

Username: {self.request.user.name}
Email: {self.request.user.email}
Didn't request this change?
If you didn't change your password, please contact us immediately at [Support Email] or [Support Phone Number].

Security Tips:

Use a strong, unique password.
Enable two-factor authentication.
Watch out for phishing emails.
For any assistance, our support team is here to help.

Thank you for your attention.

Best regards,
ABC Ltd.pvt
'''
            send_mail(
                subject = mail_subject,
                message= message,
                from_email = settings.EMAIL_HOST_USER,
                recipient_list= [self.request.user.email],
                fail_silently= True,
                    )  
            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class PasswordResetView(ModelViewSet):
    serializer_class = EmailSerialzier

    def create(self,request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.data.get('email')
            user = User.objects.filter(email=email).first()
            if user:
                encoded_pk = urlsafe_base64_encode(force_bytes(user.pk))
                token = PasswordResetTokenGenerator().make_token(user)
                # Url: localhost:8000//reset-password/<encoded_pk>/<token>/
                reset_url = reverse(
                    "password-reset",
                    kwargs = {'encoded_pk':encoded_pk,'token':token}
                )
                # Here you can add website url
                reset_url = f"http://127.0.0.1:8000/{reset_url}"
                detail = {'username':user.name,'email': user.email,'reset_url': reset_url}
                mail_subject = 'Password Reset Request for Your Account.'
                message = f'''
Dear {user.name},

We have received a request to reset the password for your account. To initiate the password reset process, please click on the link below:

{reset_url}

Please note that this link is valid for a limited time and can only be used once. If you did not request this password reset, you can safely ignore this email. Your account security is important to us, so please do not share this link with anyone.

If you encounter any issues or need further assistance, please don't hesitate to contact our support team at [Support Email] or [Support Phone Number].

Thank you for your attention to this matter.

Best regards,
PrinceLap Support Team

'''
                send_mail(
                subject = mail_subject,
                message= message,
                from_email = settings.EMAIL_HOST_USER,
                recipient_list= [email],
                fail_silently= True,
                    )  
                # password_reset_task.delay(detail) ==>> to use celery task make tasks.py file
                return Response({'message': 'Check your email to reset password','url':reset_url})
            else:
                return Response({'error': 'User does not exists'},status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.errors)
        
class PasswordResetConfirm(ModelViewSet):
    serializer_class = PasswordResetSerializer

    def partial_update(self,request,*args, **kwargs):
        serializer = self.serializer_class(data=request.data,context={'kwargs':kwargs})
        if serializer.is_valid():
            encoded_pk = kwargs.get('encoded_pk')
            pk = urlsafe_base64_decode(encoded_pk).decode()
            current_datetime = timezone.now().strftime('%Y-%m-%d %H:%M:%S')
            user = User.objects.get(pk=pk)
            mail_subject = "Your Password Has Been Changed Successfully"
            message = f'''
Dear {user.name},

We wanted to let you know that your password was successfully changed. If you made this change, no further action is needed.

Account Details:

Username: {user.name}
Email: {user.email}
Password Change Date: {current_datetime}
Didn't request this change?
If you didn't change your password, please contact us immediately at [Support Email] or [Support Phone Number].

Security Tips:

Use a strong, unique password.
Enable two-factor authentication.
Watch out for phishing emails.
For any assistance, our support team is here to help.

Thank you for your attention.

Best regards,
ABC Ltd.pvt

'''
            send_mail(
                subject = mail_subject,
                message= message,
                from_email = settings.EMAIL_HOST_USER,
                recipient_list= [user.email],
                fail_silently= True,
                    ) 
            return Response({'message': 'Your password reset complete'},status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors)



