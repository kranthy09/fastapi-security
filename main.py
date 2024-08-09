from datetime import datetime, timedelta
from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel

# secret key to generate hashed password
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "encrypted_password": "gAAAAABmtfcebBKNutoS8DcGFKb0JKCqrAIJL-omuj0gZJEMp6y0I0cgNzz0Acjpe8aMVm1DOlIA7HpQa1nXKbq_jb63ZP3y_Q==",
        "disabled": False,
    }
}


class Token(BaseModel):
    """Data model for user token"""

    access_token: str
    token_type: str


class TokenData(BaseModel):
    """Respons model for user token"""

    username: str | None = None


class User(BaseModel):
    """App user"""

    username: str
    email: str
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    """User in database data model"""

    encrypted_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


def verify_password(plain_password, encrypted_password):
    """Verify password against hash"""
    from cryptography.fernet import Fernet

    SECRET_KEY = "XvYvP_c4gBDLCLbjgz6Hc47ND_BcoMYt3Cz5pAKx1qQ="
    FERNET = Fernet(SECRET_KEY)
    print("palin_password", plain_password)
    print("encrypted_password", encrypted_password)
    enc_password = FERNET.encrypt(plain_password.encode()).decode()
    print("enc_password", enc_password)
    return enc_password == encrypted_password


def get_user(db, username: str):
    """Return user from database"""
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    """Authenticate user with username and password"""

    user = get_user(fake_db, username)
    print(user)
    if not user:
        return False
    if not verify_password(password, user.encrypted_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """Create access token for user"""
    to_encode = data.copy()
    print("data", data)
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    """Get the current user"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Returns the current active user"""
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    """Login user and return token"""
    user = authenticate_user(
        fake_users_db, form_data.username, form_data.password
    )
    print("post", user)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    """Display current user details."""
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    """return user's items"""
    return [{"item_id": "Foo", "owner": current_user.username}]
