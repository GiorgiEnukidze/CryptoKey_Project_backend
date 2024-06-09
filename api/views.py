# api/views.py

from django.contrib.auth.decorators import login_required
import logging
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.views import View
from rest_framework.response import Response
from rest_framework import status
from rest_framework import generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import csrf_exempt
from rest_framework_simplejwt.views import TokenObtainPairView
import csv
import json
from .models import PasswordEntry, SecureNote, CreditCard, IdentityCard, EncryptionKey, PasswordEntry, PasswordShare
from .serializers import (
    PasswordEntrySerializer, SecureNoteSerializer,
    CardSerializer, IdentitySerializer,
    EncryptionKeySerializer, UserSerializer,
    PasswordShareSerializer, PasswordImportSerializer,PasswordExportSerializer
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


################### obtention de token d'authetification ##########################

class MyTokenObtainPairView(TokenObtainPairView):
    permission_classes = [AllowAny]



################### view generique user ##########################

class UserListView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

class UserDetailView(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]



class ApiHomeView(View):
    def get(self, request):
        return HttpResponse("Welcome to the Cryptokey API home page!")



################### view generique paswword ##########################

class PasswordEntryListCreateView(generics.ListCreateAPIView):
    serializer_class = PasswordEntrySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return PasswordEntry.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class PasswordEntryDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = PasswordEntrySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return PasswordEntry.objects.filter(user=self.request.user)


################### view generique secure note ##########################

class SecureNoteListCreateView(generics.ListCreateAPIView):
    queryset = SecureNote.objects.all()
    serializer_class = SecureNoteSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class SecureNoteDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = SecureNote.objects.all()
    serializer_class = SecureNoteSerializer
    permission_classes = [IsAuthenticated]


################### view generique credit card ##########################

class CreditCardListCreateView(generics.ListCreateAPIView):
    queryset = CreditCard.objects.all()
    serializer_class = CardSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class CreditCardDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = CreditCard.objects.all()
    serializer_class = CardSerializer
    permission_classes = [IsAuthenticated]

################### view generique id card ##########################


class IdentityCardListCreateView(generics.ListCreateAPIView):
    queryset = IdentityCard.objects.all()
    serializer_class = IdentitySerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class IdentityCardDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = IdentityCard.objects.all()
    serializer_class = IdentitySerializer
    permission_classes = [IsAuthenticated]

################### view generique encryption key ##########################

class EncryptionKeyListCreateView(generics.ListCreateAPIView):
    queryset = EncryptionKey.objects.all()
    serializer_class = EncryptionKeySerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class EncryptionKeyDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = EncryptionKey.objects.all()
    serializer_class = EncryptionKeySerializer
    permission_classes = [IsAuthenticated]


################### verifie la force d'un mdp ##########################


def check_password_strength(password):
    length = len(password)
    has_digit = any(char.isdigit() for char in password)
    has_special_char = any(char in "!@#$%^&*()-_+=~`[]{}|;:'\",.<>?/" for char in password)

    strength = 0

    if length >= 8:
        strength += 20
    if has_digit:
        strength += 20
    if has_special_char:
        strength += 20

    return strength


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def check_password(request):
    password = request.data.get('password')
    strength = check_password_strength(password)
    return JsonResponse({"strength": strength})

################### partage de mots de passe ##########################

@api_view(['POST', 'GET'])
@permission_classes([IsAuthenticated])
def share_password(request):
    if request.method == 'POST':
        try:
            shared_with_user_id = request.data.get('shared_with_user_id')
            shared_by_user_id = request.data.get('shared_by_user_id')
            password_entry_id = request.data.get('password_entry_id')
            expiration_date = request.data.get('expiration_date')

            # Vérifier si l'utilisateur destinataire existe
            shared_with_user = User.objects.get(id=shared_with_user_id)

            # Vérifier si l'utilisateur envoyeur existe
            shared_by_user = User.objects.get(id=shared_by_user_id)

            # Récupérer l'entrée de mot de passe à partager
            password_entry = PasswordEntry.objects.get(id=password_entry_id)

            # Créer une instance de PasswordShare
            password_share = PasswordShare.objects.create(
                password_entry=password_entry,
                shared_with_user=shared_with_user,
                shared_by_user=shared_by_user,
                expiration_date=expiration_date
            )

            # Serializer l'instance de PasswordShare
            serializer = PasswordShareSerializer(password_share)

            # Retourner la réponse avec les données sérialisées
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            # En cas d'erreur, retourner un message d'erreur
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    elif request.method == 'GET':
        try:
            # Filtrer les mots de passe partagés avec l'utilisateur connecté
            shared_passwords = PasswordShare.objects.filter(shared_with_user=request.user)

            # Initialiser une liste pour stocker les données sérialisées
            serialized_data = []

            # Boucler sur les mots de passe partagés pour les sérialiser
            for shared_password in shared_passwords:
                # Créer un dictionnaire avec les données nécessaires
                data = {
                    'id': shared_password.id,
                    'password_entry_id': shared_password.password_entry.id,
                    'site_name': shared_password.password_entry.site_name,
                    'username': shared_password.password_entry.username,
                    'expiration_date': shared_password.expiration_date,
                    # Ajoutez d'autres champs si nécessaire
                }
                # Ajouter le dictionnaire à la liste
                serialized_data.append(data)

            # Retourner les données sérialisées
            return Response(serialized_data, status=status.HTTP_200_OK)

        except Exception as e:
            # En cas d'erreur, retourner un message d'erreur
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        # Si la méthode HTTP n'est pas autorisée, retourner un message approprié
        return Response({'message': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)



################### import de mdp ##########################


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def import_passwords(request):
    if request.method == 'POST':
        try:
            # Récupérer le format d'importation (JSON ou CSV)
            format = request.data.get('format')
            if format not in ['json', 'csv']:
                return JsonResponse({"error": "Invalid import format specified"}, status=400)

            if format == 'json':
                # Convertir les données JSON en dictionnaire
                imported_data = json.loads(request.data.get('data'))
                serializer = PasswordImportSerializer(data=imported_data, many=True)
            elif format == 'csv':
                # Lire les données CSV et les convertir en dictionnaire
                csv_data = request.FILES['file'].read().decode('utf-8').splitlines()
                csv_reader = csv.DictReader(csv_data)
                imported_data = list(csv_reader)
                serializer = PasswordImportSerializer(data=imported_data, many=True)
            
            if serializer.is_valid():
                # Enregistrer les mots de passe importés dans la base de données
                serializer.save(user=request.user)
                return JsonResponse({"status": "Passwords imported successfully"}, status=200)
            else:
                return JsonResponse({"error": serializer.errors}, status=400)
        except Exception as e:
            # En cas d'erreur, retourner un message d'erreur
            return JsonResponse({'error': str(e)}, status=500)
    else:
        # Si la méthode HTTP n'est pas autorisée, retourner un message approprié
        return JsonResponse({'message': 'Method not allowed'}, status=405)



################### export de mdp ##########################

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def export_passwords(request):
    if request.method == 'POST':
        try:
            # Récupérer tous les mots de passe de l'utilisateur actuel
            passwords = PasswordEntry.objects.filter(user=request.user)
            
            # Vérifier le format demandé (JSON ou CSV)
            format = request.data.get('format', 'json')  # Par défaut, exportation en JSON
            
            if format == 'json':
                # Sérialiser les mots de passe en JSON
                passwords_data = [{'id': p.id, 'user': p.user.id, 'site_name': p.site_name, 'site_url': p.site_url, 
                                   'username': p.username, 'password': p.password, 'created_at': p.created_at, 
                                   'updated_at': p.updated_at} for p in passwords]

                # Retourner les mots de passe exportés au format JSON
                return JsonResponse(passwords_data, safe=False)
            elif format == 'csv':
                # Créer un fichier CSV temporaire
                response = HttpResponse(content_type='text/csv')
                response['Content-Disposition'] = 'attachment; filename="passwords.csv"'

                # Créer un écrivain CSV
                writer = csv.writer(response)
                # Écrire l'en-tête CSV
                writer.writerow(['id', 'user', 'site_name', 'site_url', 'username', 'password', 'created_at', 'updated_at'])
                # Écrire les données de chaque mot de passe dans le fichier CSV
                for password in passwords:
                    writer.writerow([password.id, password.user.id, password.site_name, password.site_url, 
                                     password.username, password.password, password.created_at, password.updated_at])

                return response
            else:
                # Si le format spécifié n'est ni JSON ni CSV, retourner une erreur
                return JsonResponse({'error': 'Invalid format specified'}, status=400)
        except Exception as e:
            # En cas d'erreur, retourner un message d'erreur
            return JsonResponse({'error': str(e)}, status=500)
    else:
        # Si la méthode HTTP n'est pas autorisée, retourner un message approprié
        return JsonResponse({'message': 'Method not allowed'}, status=405)

################### USERS ##########################

@api_view(['POST']) #connection 
def user_login(request):
    if request.method == 'POST':
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return JsonResponse({'message': 'Login successful'}, status=200)
        else:
            return JsonResponse({'message': 'Invalid username or password'}, status=400)


@api_view(['POST']) #création d'un nouvel utilisateur
def user_register(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        username = serializer.validated_data.get('username')
        email = serializer.validated_data.get('email')
        first_name = serializer.validated_data.get('first_name')
        last_name = serializer.validated_data.get('last_name')
        password = request.data.get('password')  # Assuming password is still required for creation

        if not password:
            return Response({'message': 'Password is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        if User.objects.filter(username=username).exists():
            return Response({'message': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)
        
        user = User.objects.create_user(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=password
        )
        
        if user:
            return Response({'message': 'Registration successful', 'user': UserSerializer(user).data}, status=status.HTTP_201_CREATED)
        else:
            return Response({'message': 'Registration failed'}, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

@api_view(['PATCH']) 
@permission_classes([IsAuthenticated])
def update_profile(request, user_id):
    if request.method == 'PATCH':
        try:
            user_profile = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'message': 'User profile does not exist'}, status=status.HTTP_404_NOT_FOUND)

        # Update profile fields
        user_profile.username = request.data.get('username', user_profile.username)
        user_profile.email = request.data.get('email', user_profile.email)
        user_profile.first_name = request.data.get('first_name', user_profile.first_name)
        user_profile.last_name = request.data.get('last_name', user_profile.last_name)

        # Check if new password is provided
        new_password = request.data.get('password')
        if new_password:
            # Set new password
            user_profile.set_password(new_password)

        # Save user profile
        user_profile.save()

        return Response({'message': 'Profile updated successfully', 'user': UserSerializer(user_profile).data}, status=status.HTTP_200_OK)
    
    return Response({'message': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)




@api_view(['GET']) # récuppération des donnée pour la page profil
@permission_classes([IsAuthenticated])
def get_user_profile(request):
    user = request.user
    serializer = UserSerializer(user)
    return Response(serializer.data)



###################  PASSWORD ##########################

@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_password(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            site_name = data.get('site_name')
            site_url = data.get('site_url')
            username = data.get('username')
            password = data.get('password')

            # Logging the received data for debugging
            print(f"Received data: {data}")

            if not site_name or not site_url or not username or not password:
                return JsonResponse({'message': 'All fields are required'}, status=400)

            password_entry = PasswordEntry.objects.create(
                user=request.user,
                site_name=site_name,
                site_url=site_url,
                username=username,
                password=password
            )
            password_entry.save()

            serializer = PasswordEntrySerializer(password_entry)
            return JsonResponse(serializer.data, status=201)
        except Exception as e:
            print(f"Exception: {e}")
            return JsonResponse({'message': 'Bad request', 'error': str(e)}, status=400)
    else:
        return JsonResponse({'message': 'Method not allowed'}, status=405)
    

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_passwords(request):
    user = request.user
    passwords = PasswordEntry.objects.filter(user=user)
    for password in passwords:
        password.site = password.site or 'Unknown site'
        password.username = password.username or 'Unknown username'
        password.password = password.password or 'No password'
    serializer = PasswordEntrySerializer(passwords, many=True)
    return JsonResponse(serializer.data, status=200, safe=False)


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def update_password(request, password_id):  # Ajout de password_id comme paramètre
    if request.method == 'PATCH':
        try:
            password_entry = PasswordEntry.objects.get(id=password_id, user=request.user)
        except PasswordEntry.DoesNotExist:
            return JsonResponse({'message': 'Password entry does not exist'}, status=404)

        password_entry.site_name = request.data.get('site_name', password_entry.site_name)
        password_entry.site_url = request.data.get('site_url', password_entry.site_url)
        password_entry.username = request.data.get('username', password_entry.username)
        password_entry.password = request.data.get('password', password_entry.password)
        password_entry.save()

        serializer = PasswordEntrySerializer(password_entry)
        return JsonResponse(serializer.data, status=200)
    
    return JsonResponse({'message': 'Method not allowed'}, status=405)

@login_required
def password_list(request):
    passwords = PasswordEntry.objects.filter(user=request.user)
    return render(request, 'password_list.html', {'passwords': passwords})

@csrf_exempt
@api_view(['DELETE'])
@login_required
def delete_password(request, password_id):
    try:
        password = PasswordEntry.objects.get(id=password_id, user=request.user)
        if password:
            password.delete()
            return JsonResponse({'message': 'Password deleted successfully'}, status=204)
        else:
            return JsonResponse({'error': 'Password not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    

################### SECURE NOTE ##########################


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_secure_note(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            title = data.get('title')
            content = data.get('content')

            if not title or not content:
                return JsonResponse({'message': 'All fields are required'}, status=400)

            secure_note = SecureNote.objects.create(
                user=request.user,
                title=title,
                content=content
            )
            secure_note.save()

            serializer = SecureNoteSerializer(secure_note)
            return JsonResponse(serializer.data, status=201)
        except Exception as e:
            return JsonResponse({'message': 'Bad request', 'error': str(e)}, status=400)
    else:
        return JsonResponse({'message': 'Method not allowed'}, status=405)

@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def update_secure_note(request, note_id):
    if request.method == 'PATCH':
        try:
            secure_note = SecureNote.objects.get(id=note_id, user=request.user)
        except SecureNote.DoesNotExist:
            return JsonResponse({'message': 'Secure note does not exist'}, status=404)

        secure_note.title = request.data.get('title', secure_note.title)
        secure_note.content = request.data.get('content', secure_note.content)
        secure_note.save()

        serializer = SecureNoteSerializer(secure_note)
        return JsonResponse(serializer.data, status=200)
    
    return JsonResponse({'message': 'Method not allowed'}, status=405)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_secure_note(request, note_id):
    try:
        secure_note = SecureNote.objects.get(id=note_id, user=request.user)
        if secure_note:
            secure_note.delete()
            return JsonResponse({'message': 'Secure note deleted successfully'}, status=204)
        else:
            return JsonResponse({'error': 'Secure note not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def secure_note_list(request):
    secure_notes = SecureNote.objects.filter(user=request.user)
    return render(request, 'secure_note_list.html', {'secure_notes': secure_notes})




################### CREDIT CARD ##########################



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_credit_card(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            card_number = data.get('card_number')
            expiry_date = data.get('expiry_date')
            cvv = data.get('cvv')
            cardholder_name = data.get('cardholder_name')

            if not card_number or not expiry_date or not cvv or not cardholder_name:
                return JsonResponse({'message': 'All fields are required'}, status=400)

            credit_card = CreditCard.objects.create(
                user=request.user,
                card_number=card_number,
                expiry_date=expiry_date,
                cvv=cvv,
                cardholder_name=cardholder_name
            )
            credit_card.save()

            serializer = CardSerializer(credit_card)
            return JsonResponse(serializer.data, status=201)
        except Exception as e:
            return JsonResponse({'message': 'Bad request', 'error': str(e)}, status=400)
    else:
        return JsonResponse({'message': 'Method not allowed'}, status=405)

@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def update_credit_card(request, card_id):
    if request.method == 'PATCH':
        try:
            credit_card = CreditCard.objects.get(id=card_id, user=request.user)
        except CreditCard.DoesNotExist:
            return JsonResponse({'message': 'Credit card does not exist'}, status=404)

        credit_card.card_number = request.data.get('card_number', credit_card.card_number)
        credit_card.expiry_date = request.data.get('expiry_date', credit_card.expiry_date)
        credit_card.cvv = request.data.get('cvv', credit_card.cvv)
        credit_card.cardholder_name = request.data.get('cardholder_name', credit_card.cardholder_name)
        credit_card.save()

        serializer = CardSerializer(credit_card)
        return JsonResponse(serializer.data, status=200)
    
    return JsonResponse({'message': 'Method not allowed'}, status=405)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_credit_card(request, card_id):
    try:
        credit_card = CreditCard.objects.get(id=card_id, user=request.user)
        if credit_card:
            credit_card.delete()
            return JsonResponse({'message': 'Credit card deleted successfully'}, status=204)
        else:
            return JsonResponse({'error': 'Credit card not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def credit_card_list(request):
    credit_cards = CreditCard.objects.filter(user=request.user)
    return render(request, 'credit_card_list.html', {'credit_cards': credit_cards})



################### IDENTITY CARD ##########################

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_identity_card(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            id_number = data.get('id_number')
            expiry_date = data.get('expiry_date')
            name = data.get('name')
            surname = data.get('surname')
            nationality = data.get('nationality')
            date_of_issue = data.get('date_of_issue')
            date_of_birth = data.get('date_of_birth')

            if not id_number or not expiry_date or not name or not surname or not nationality or not date_of_issue or not date_of_birth:
                return JsonResponse({'message': 'All fields are required'}, status=400)

            identity_card = IdentityCard.objects.create(
                user=request.user,
                id_number=id_number,
                expiry_date=expiry_date,
                name=name,
                surname=surname,
                nationality=nationality,
                date_of_issue=date_of_issue,
                date_of_birth=date_of_birth
            )
            identity_card.save()

            serializer = IdentitySerializer(identity_card)
            return JsonResponse(serializer.data, status=201)
        except Exception as e:
            return JsonResponse({'message': 'Bad request', 'error': str(e)}, status=400)
    else:
        return JsonResponse({'message': 'Method not allowed'}, status=405)

@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def update_identity_card(request, card_id):
    if request.method == 'PATCH':
        try:
            identity_card = IdentityCard.objects.get(id=card_id, user=request.user)
        except IdentityCard.DoesNotExist:
            return JsonResponse({'message': 'Identity card does not exist'}, status=404)

        identity_card.id_number = request.data.get('id_number', identity_card.id_number)
        identity_card.expiry_date = request.data.get('expiry_date', identity_card.expiry_date)
        identity_card.name = request.data.get('name', identity_card.name)
        identity_card.surname = request.data.get('surname', identity_card.surname)
        identity_card.nationality = request.data.get('nationality', identity_card.nationality)
        identity_card.date_of_issue = request.data.get('date_of_issue', identity_card.date_of_issue)
        identity_card.date_of_birth = request.data.get('date_of_birth', identity_card.date_of_birth)
        identity_card.save()

        serializer = IdentitySerializer(identity_card)
        return JsonResponse(serializer.data, status=200)
    
    return JsonResponse({'message': 'Method not allowed'}, status=405)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_identity_card(request, card_id):
    try:
        identity_card = IdentityCard.objects.get(id=card_id, user=request.user)
        if identity_card:
            identity_card.delete()
            return JsonResponse({'message': 'Identity card deleted successfully'}, status=204)
        else:
            return JsonResponse({'error': 'Identity card not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def identity_card_list(request):
    identity_cards = IdentityCard.objects.filter(user=request.user)
    return render(request, 'identity_card_list.html', {'identity_cards': identity_cards})

################### ENCRYPTION KEY ##########################

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_encryption_key(request):
    print('Authorization Token:', request.headers.get('Authorization'))  # Log the authorization token

    if request.method == 'POST':
        try:
            # Parse the request data
            data = json.loads(request.body)
            titles = data.get('titles')
            key = data.get('key')

            # Check if titles and key are provided
            if not key or not titles:
                return JsonResponse({'message': 'All fields are required'}, status=400)

            # Create the encryption key
            encryption_key = EncryptionKey.objects.create(
                user=request.user,
                titles=titles,
                key=key
            )

            # Serialize the encryption key
            serializer = EncryptionKeySerializer(encryption_key)

            # Return the serialized data
            return JsonResponse(serializer.data, status=201)
        except Exception as e:
            # Log the exception and return a bad request response
            print('Exception:', str(e))
            return JsonResponse({'message': 'Bad request', 'error': str(e)}, status=400)
    else:
        # Return a method not allowed response
        return JsonResponse({'message': 'Method not allowed'}, status=405)


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def update_encryption_key(request, key_id):
    try:
        encryption_key = EncryptionKey.objects.get(id=key_id, user=request.user)
    except EncryptionKey.DoesNotExist:
        return JsonResponse({'message': 'Encryption key does not exist'}, status=404)

    encryption_key.titles = request.data.get('title', encryption_key.titles)
    encryption_key.key = request.data.get('key', encryption_key.key)
    encryption_key.save()

    serializer = EncryptionKeySerializer(encryption_key)
    return JsonResponse(serializer.data, status=200)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_encryption_key(request, key_id):
    try:
        encryption_key = EncryptionKey.objects.get(id=key_id, user=request.user)
        encryption_key.delete()
        return JsonResponse({'message': 'Encryption key deleted successfully'}, status=204)
    except EncryptionKey.DoesNotExist:
        return JsonResponse({'error': 'Encryption key not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def encryption_key_list(request):
    encryption_keys = EncryptionKey.objects.filter(user=request.user)
    return render(request, 'encryption_key_list.html', {'encryption_keys': encryption_keys})
