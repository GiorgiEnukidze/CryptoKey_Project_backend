#api/models
from datetime import timezone
from django.utils import timezone
from django.db import models
from django.contrib.auth.models import User

class PasswordEntry(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    site_name = models.CharField(max_length=255)  # Nom du site pour lequel le mot de passe est utilisé
    site_url = models.URLField()  # URL du site
    username = models.CharField(max_length=150)  # Nom d'utilisateur pour le site
    password = models.CharField(max_length=256)  # Mot de passe
    created_at = models.DateTimeField(auto_now_add=True)  # Date de création
    updated_at = models.DateTimeField(auto_now=True)  # Date de la dernière mise à jour

    def __str__(self):
        return self.site_name  # Utilisation de l'attribut site_name pour la représentation en chaîne
    

class SecureNote(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)  # Titre de la note sécurisée
    content = models.TextField()  # Contenu de la note
    created_at = models.DateTimeField(auto_now_add=True)  # Date de création
    updated_at = models.DateTimeField(auto_now=True)  # Date de la dernière mise à jour

    def __str__(self):
        return self.title  # Utilisation de l'attribut title pour la représentation en chaîne

class CreditCard(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    card_number = models.CharField(max_length=16)  # Numéro de carte
    expiry_date = models.DateField()  # Date d'expiration
    cvv = models.CharField(max_length=4)  # Code CVV
    cardholder_name = models.CharField(max_length=255)  # Nom du titulaire de la carte
    created_at = models.DateTimeField(auto_now_add=True)  # Date de création
    updated_at = models.DateTimeField(auto_now=True)  # Date de la dernière mise à jour

    def __str__(self):
        return self.cardholder_name  # Utilisation de l'attribut cardholder_name pour la représentation en chaîne

class IdentityCard(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=255, default="Unknown")  # prénom
    surname = models.CharField(max_length=255, default="Unknown")  # nom
    nationality = models.CharField(max_length=255, default="Unknown")  # nationalite
    id_number = models.CharField(max_length=50, default="Unknown")  # Numéro d'identité
    date_of_issue = models.DateTimeField(default=timezone.now)  # date de quand il l'a reçu
    expiry_date = models.DateTimeField(default=timezone.now)  # Date d'expiration
    date_of_birth = models.DateTimeField(default=timezone.now)  # jour de naissance
    created_at = models.DateTimeField(auto_now_add=True)  # Date de création
    updated_at = models.DateTimeField(auto_now=True)  # Date de la dernière mise à jour

class EncryptionKey(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    titles = models.TextField(max_length=255, default="Unknown")  # titre
    key = models.TextField()  # Clé de chiffrement
    created_at = models.DateTimeField(auto_now_add=True)  # Date de création
    updated_at = models.DateTimeField(auto_now=True)  # Date de la dernière mise à jour

    def __str__(self):
        return f"{self.titles} - {self.key}"
    
class PasswordShare(models.Model):
    password_entry = models.ForeignKey('PasswordEntry', on_delete=models.CASCADE)
    shared_with_user = models.ForeignKey(User, related_name='shared_passwords', on_delete=models.CASCADE)
    shared_by_user = models.ForeignKey(User, related_name='shared_by_user', on_delete=models.CASCADE)
    expiration_date = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('password_entry', 'shared_with_user', 'shared_by_user')


