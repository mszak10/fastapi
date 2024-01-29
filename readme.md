# Integracja FastAPI-Flask

Ten projekt demonstruje integrację FastAPI jako usługi backendowej i Flask jako usługi frontendowej dla prostego systemu uwierzytelniania użytkowników i zarządzania profilami.

## Struktura projektu
- **main.py**: Zawiera aplikację FastAPI do uwierzytelniania użytkowników, generowania tokenów i zarządzania profilami użytkowników.
- **app.py**: Zawiera aplikację Flask do obsługi interfejsu użytkownika, rejestracji użytkownika, logowania, profilu i usuwania konta.
- **templates/**: Zawiera szablony HTML dla frontendu.

## Wymagania wstępne
- Python 3.x
- FastAPI
- Flask
- PyJWT
- SQLite3 (dla bazy danych)
- uvicorn

## Instalacja
1. Sklonuj repozytorium:

```bash
git clone https://github.com/mszak10/fastapi.git
```

2. Zainstaluj wymagane zależności:
```bash
pip install -r requirements.txt
```
## Uruchamianie aplikacji
- Uruchom backend FastAPI:
```bash
uvicorn main:app --reload
```
- Uruchom frontend Flask:
```bash
python app.py
```
Otwórz przeglądarkę internetową i odwiedź stronę http://localhost:5000, aby uzyskać dostęp do aplikacji.

## Użycie
- Odwiedź stronę główną, aby się zarejestrować lub zalogować.
- Po zalogowaniu możesz przejść do swojego profilu, zaktualizować informacje i usunąć konto.

## Dokumentacja API
Dostępna pod adresem http://127.0.0.1:8000/docs