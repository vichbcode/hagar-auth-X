"""Validation des entrées et politique de mots de passe (Hagar-Auth)."""
import re
import unicodedata

ADMIN_PASSWORD_MIN_LENGTH = 12
PROJECT_PASSWORD_MIN_LENGTH = 12
END_USER_PASSWORD_MIN_LENGTH = 8

MAX_USERNAME_LENGTH = 80
MAX_IDENTIFIER_LENGTH = 150
MAX_FIELD_VALUE_LENGTH = 1000
MAX_LABEL_LENGTH = 100
MAX_NAME_LENGTH = 100

USERNAME_RE = re.compile(r"^[\w.\-]{3,80}$", re.UNICODE)

ALLOWED_FIELD_TYPES = frozenset({
    "text", "email", "password", "number", "date", "time", "datetime-local",
    "month", "week", "url", "tel", "color", "checkbox", "radio", "range",
    "search", "hidden",
})

PASSWORD_RULES_HINT = (
    "12 caractères minimum, dont 3 parmi : minuscule, majuscule, chiffre, symbole."
)


def _class_count(password: str) -> int:
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    return sum((has_lower, has_upper, has_digit, has_symbol))


def _is_well_formed(password: str) -> bool:
    return password == password.strip() and not any(
        unicodedata.category(c) in ("Cc", "Cf", "Co", "Cs") for c in password
    )


def validate_admin_password(password) -> str | None:
    """Retourne un message d'erreur en français, ou None si le mdp est acceptable."""
    if not password:
        return "Mot de passe requis."
    if len(password) < ADMIN_PASSWORD_MIN_LENGTH:
        return f"Le mot de passe doit contenir au moins {ADMIN_PASSWORD_MIN_LENGTH} caractères."
    if _class_count(password) < 3:
        return f"Le mot de passe doit contenir au moins 3 des 4 catégories : minuscule, majuscule, chiffre, symbole."
    if not _is_well_formed(password):
        return "Le mot de passe contient des caractères non autorisés."
    return None


def validate_project_password(password) -> str | None:
    if not password:
        return "Mot de passe requis."
    if len(password) < PROJECT_PASSWORD_MIN_LENGTH:
        return f"Le mot de passe du Hagar doit contenir au moins {PROJECT_PASSWORD_MIN_LENGTH} caractères."
    if _class_count(password) < 3:
        return f"Le mot de passe du Hagar doit contenir au moins 3 des 4 catégories : minuscule, majuscule, chiffre, symbole."
    if not _is_well_formed(password):
        return "Le mot de passe contient des caractères non autorisés."
    return None


def validate_end_user_password(password) -> str | None:
    if not password:
        return "Mot de passe requis."
    if len(password) < END_USER_PASSWORD_MIN_LENGTH:
        return f"Le mot de passe doit contenir au moins {END_USER_PASSWORD_MIN_LENGTH} caractères."
    if not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        return "Le mot de passe doit contenir au moins une lettre et un chiffre."
    if not _is_well_formed(password):
        return "Le mot de passe contient des caractères non autorisés."
    return None


def validate_username(username) -> str | None:
    if not username:
        return "Pseudo requis."
    if len(username) > MAX_USERNAME_LENGTH:
        return f"Le pseudo ne peut pas dépasser {MAX_USERNAME_LENGTH} caractères."
    if not USERNAME_RE.match(username):
        return "Pseudo invalide : 3 à 80 caractères, lettres/chiffres/underscore/point/tiret, sans espace."
    return None


def validate_label(label) -> tuple[str | None, str | None]:
    """Nettoie et valide un libellé de champ. Retourne (libellé_propre, erreur)."""
    label = (label or "").strip()
    if not label:
        return None, "Le nom du champ est requis."
    if len(label) > MAX_LABEL_LENGTH:
        return None, f"Le nom du champ ne peut pas dépasser {MAX_LABEL_LENGTH} caractères."
    if any(unicodedata.category(c) in ("Cc", "Cf", "Co", "Cs") for c in label):
        return None, "Le nom du champ contient des caractères de contrôle interdits."
    return label, None
