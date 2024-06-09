# api/serializers.py
from rest_framework import serializers
from .models import PasswordEntry, SecureNote, CreditCard, IdentityCard, EncryptionKey, User, PasswordShare

class PasswordEntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordEntry
        fields = ['id', 'user', 'site_name', 'site_url', 'username', 'password', 'created_at', 'updated_at']

class SecureNoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecureNote
        fields = ['id', 'user', 'title', 'content', 'created_at', 'updated_at']

class CardSerializer(serializers.ModelSerializer):
    class Meta:
        model = CreditCard
        fields = ['id', 'user', 'card_number', 'expiry_date', 'cvv', 'cardholder_name', 'created_at', 'updated_at']

class IdentitySerializer(serializers.ModelSerializer):
    class Meta:
        model = IdentityCard
        fields = ['id', 'user', 'name', 'surname', 'nationality', 'id_number', 'date_of_issue', 'expiry_date', 'date_of_birth', 'created_at', 'updated_at']


class EncryptionKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = EncryptionKey
        fields = ['id', 'user', 'titles', 'key', 'created_at', 'updated_at']


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)  

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'password']  

class PasswordShareSerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordShare
        fields = ['id', 'password_entry', 'shared_with_user', 'shared_by_user', 'expiration_date', 'created_at', 'updated_at']

class PasswordImportSerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordEntry
        fields = ['site_name', 'site_url', 'username', 'password', 'created_at', 'updated_at']

class PasswordExportSerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordEntry
        fields = ['site_name', 'site_url', 'username', 'password', 'created_at', 'updated_at']