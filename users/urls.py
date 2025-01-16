from network.urls import path
from .views import  UserRegisterView, UserLoginView, ProtectedResourceView

urlpatterns = [
    path('register/', UserRegisterView.as_view(), name="register"),
    path('login/', UserLoginView.as_view(), name='login'),
    path('protected-resource/', ProtectedResourceView.as_view(), name='protected-resource'),
]
