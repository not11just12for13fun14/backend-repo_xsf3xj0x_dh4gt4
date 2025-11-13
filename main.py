import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents

# Environment / Auth settings
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

app = FastAPI(title="TechCart API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Utility functions
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: str
    username: str
    email: EmailStr
    role: str


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    try:
        from bson import ObjectId
        user = db["user"].find_one({"_id": ObjectId(user_id)})
    except Exception:
        user = None

    if not user:
        raise credentials_exception
    return user


# Routes
@app.get("/")
def root():
    return {"message": "TechCart API is running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


# Auth endpoints
@app.post("/auth/register", response_model=UserOut)
def register(payload: UserCreate):
    # check existing
    if db["user"].find_one({"$or": [{"username": payload.username}, {"email": payload.email}] }):
        raise HTTPException(status_code=400, detail="Username or email already exists")

    doc = {
        "username": payload.username,
        "email": payload.email,
        "password_hash": get_password_hash(payload.password),
        "role": "customer",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    result = db["user"].insert_one(doc)
    return {
        "id": str(result.inserted_id),
        "username": doc["username"],
        "email": doc["email"],
        "role": doc["role"],
    }


@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = db["user"].find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    access_token = create_access_token({"sub": str(user["_id"])})
    return {"access_token": access_token, "token_type": "bearer"}


# Product and category models
class CategoryIn(BaseModel):
    name: str
    slug: str
    description: Optional[str] = None


class ProductIn(BaseModel):
    name: str
    category: str
    brand: Optional[str] = None
    price: float
    stock: int
    image: Optional[str] = None
    description: Optional[str] = None
    specs: Optional[dict] = None


# Admin guard
def require_admin(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    return user


# Category endpoints
@app.post("/categories", dependencies=[Depends(require_admin)])
def create_category(payload: CategoryIn):
    if db["category"].find_one({"$or": [{"slug": payload.slug}, {"name": payload.name}]}):
        raise HTTPException(status_code=400, detail="Category exists")
    cid = create_document("category", payload.model_dump())
    return {"id": cid, **payload.model_dump()}


@app.get("/categories")
def list_categories():
    items = get_documents("category")
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


# Product endpoints
@app.post("/products", dependencies=[Depends(require_admin)])
def create_product(payload: ProductIn):
    if not db["category"].find_one({"slug": payload.category}):
        raise HTTPException(status_code=400, detail="Category not found")
    pid = create_document("product", payload.model_dump())
    return {"id": pid, **payload.model_dump()}


@app.get("/products")
def list_products(q: Optional[str] = None, category: Optional[str] = None):
    filter_q = {}
    if q:
        filter_q["name"] = {"$regex": q, "$options": "i"}
    if category:
        filter_q["category"] = category
    items = list(db["product"].find(filter_q).limit(100))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


@app.get("/products/{product_id}")
def get_product(product_id: str):
    from bson import ObjectId
    try:
        doc = db["product"].find_one({"_id": ObjectId(product_id)})
    except Exception:
        raise HTTPException(status_code=404, detail="Product not found")
    if not doc:
        raise HTTPException(status_code=404, detail="Product not found")
    doc["id"] = str(doc.pop("_id"))
    return doc


# Cart endpoints (per-user)
class CartItemIn(BaseModel):
    product_id: str
    quantity: int


@app.get("/cart")
def get_cart(user=Depends(get_current_user)):
    items = list(db["cartitem"].find({"user_id": str(user["_id"])}))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


@app.post("/cart")
def add_to_cart(payload: CartItemIn, user=Depends(get_current_user)):
    from bson import ObjectId
    # Validate product
    try:
        product = db["product"].find_one({"_id": ObjectId(payload.product_id)})
    except Exception:
        product = None
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    existing = db["cartitem"].find_one({"user_id": str(user["_id"]), "product_id": payload.product_id})
    if existing:
        db["cartitem"].update_one({"_id": existing["_id"]}, {"$inc": {"quantity": payload.quantity}, "$set": {"updated_at": datetime.now(timezone.utc)}})
        return {"id": str(existing["_id"]), "user_id": str(user["_id"]), "product_id": payload.product_id, "quantity": existing["quantity"] + payload.quantity}

    doc = {
        "user_id": str(user["_id"]),
        "product_id": payload.product_id,
        "quantity": payload.quantity,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["cartitem"].insert_one(doc)
    return {"id": str(res.inserted_id), **doc}


@app.delete("/cart/{item_id}")
def remove_from_cart(item_id: str, user=Depends(get_current_user)):
    from bson import ObjectId
    try:
        doc = db["cartitem"].find_one({"_id": ObjectId(item_id), "user_id": str(user["_id"])})
    except Exception:
        doc = None
    if not doc:
        raise HTTPException(status_code=404, detail="Cart item not found")
    db["cartitem"].delete_one({"_id": doc["_id"]})
    return {"status": "removed"}


# Checkout / Orders
class CheckoutIn(BaseModel):
    items: List[CartItemIn]


@app.post("/checkout")
def checkout(payload: CheckoutIn, user=Depends(get_current_user)):
    from bson import ObjectId
    total = 0.0
    order_items = []

    for it in payload.items:
        try:
            product = db["product"].find_one({"_id": ObjectId(it.product_id)})
        except Exception:
            product = None
        if not product:
            raise HTTPException(status_code=404, detail=f"Product not found: {it.product_id}")
        if product.get("stock", 0) < it.quantity:
            raise HTTPException(status_code=400, detail=f"Insufficient stock for {product['name']}")
        price = float(product.get("price", 0))
        total += price * it.quantity
        order_items.append({"product_id": it.product_id, "quantity": it.quantity, "price": price})

    order_doc = {
        "user_id": str(user["_id"]),
        "status": "pending",
        "total_price": round(total, 2),
        "items": order_items,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["order"].insert_one(order_doc)

    # Decrement stock
    for it in order_items:
        db["product"].update_one({"_id": ObjectId(it["product_id"])}, {"$inc": {"stock": -it["quantity"]}})

    # Clear user's cart
    db["cartitem"].delete_many({"user_id": str(user["_id"])})

    return {"order_id": str(res.inserted_id), **order_doc}


@app.get("/orders")
def list_orders(user=Depends(get_current_user)):
    filt = {}
    if user.get("role") != "admin":
        filt = {"user_id": str(user["_id"])}
    items = list(db["order"].find(filt).sort("created_at", -1))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


# Simple seed endpoint to create default categories and products (admin only)
@app.post("/seed", dependencies=[Depends(require_admin)])
def seed():
    categories = [
        {"name": "Processors", "slug": "cpu"},
        {"name": "Graphics Cards", "slug": "gpu"},
        {"name": "Motherboards", "slug": "motherboard"},
        {"name": "Memory (RAM)", "slug": "ram"},
        {"name": "Storage", "slug": "storage"},
        {"name": "Power Supplies", "slug": "psu"},
        {"name": "Accessories", "slug": "accessories"},
    ]

    for c in categories:
        if not db["category"].find_one({"slug": c["slug"]}):
            create_document("category", c)

    sample_products = [
        {"name": "Intel Core i7-12700K", "category": "cpu", "brand": "Intel", "price": 349.99, "stock": 10, "image": None, "description": "12th Gen 12-Core Processor"},
        {"name": "AMD Ryzen 7 5800X", "category": "cpu", "brand": "AMD", "price": 249.99, "stock": 8},
        {"name": "NVIDIA GeForce RTX 4070", "category": "gpu", "brand": "NVIDIA", "price": 599.99, "stock": 5},
        {"name": "Corsair Vengeance 16GB DDR4", "category": "ram", "brand": "Corsair", "price": 59.99, "stock": 25},
        {"name": "Samsung 980 PRO 1TB NVMe SSD", "category": "storage", "brand": "Samsung", "price": 129.99, "stock": 15},
        {"name": "ASUS ROG Strix Z690-E", "category": "motherboard", "brand": "ASUS", "price": 349.99, "stock": 6},
        {"name": "EVGA 750W Gold PSU", "category": "psu", "brand": "EVGA", "price": 119.99, "stock": 12},
        {"name": "Logitech G Pro Mechanical Keyboard", "category": "accessories", "brand": "Logitech", "price": 99.99, "stock": 20},
    ]

    for p in sample_products:
        if not db["product"].find_one({"name": p["name"]}):
            create_document("product", p)

    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
