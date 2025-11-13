"""
Database Schemas for TechCart

Each Pydantic model corresponds to a MongoDB collection. Collection name is the
lowercase class name.
"""
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, EmailStr


class User(BaseModel):
    username: str = Field(..., min_length=3, max_length=30)
    email: EmailStr
    password_hash: str = Field(..., description="BCrypt hash of the password")
    role: Literal["customer", "admin"] = "customer"


class Category(BaseModel):
    name: str = Field(..., min_length=2)
    slug: str = Field(..., min_length=2)
    description: Optional[str] = None


class Product(BaseModel):
    name: str
    category: str = Field(..., description="Category slug")
    brand: Optional[str] = None
    price: float = Field(..., ge=0)
    stock: int = Field(..., ge=0)
    image: Optional[str] = None
    description: Optional[str] = None
    specs: Optional[dict] = None
    rating: float = 0
    ratings_count: int = 0


class CartItem(BaseModel):
    user_id: str
    product_id: str
    quantity: int = Field(..., ge=1)


class OrderItem(BaseModel):
    product_id: str
    quantity: int = Field(..., ge=1)
    price: float = Field(..., ge=0)


class Order(BaseModel):
    user_id: str
    status: Literal["pending", "paid", "shipped", "completed", "cancelled"] = "pending"
    total_price: float = 0
    items: List[OrderItem]
