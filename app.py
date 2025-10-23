import os
import json
import logging
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
from flasgger import Swagger

# =============================================================================
#  App & DB Setup
# =============================================================================

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_super_secret_key'  # Change this in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wishlist.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
swagger = Swagger(app)

DB_FILE = 'wishlist.db'
SETUP_FILE = 'setup.json'

# =============================================================================
#  Models
# =============================================================================


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    wishlists = db.relationship(
        'Wishlist', backref='owner', lazy=True, cascade="all, delete-orphan")

    def __init__(self, username, email):
        self.username = username
        self.email = email

    def set_password(self, password):
        self.password_hash = password

    def check_password(self, password):
        return self.password_hash == password


class Wishlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    products = db.relationship(
        'Product', backref='wishlist', lazy=True, cascade="all, delete-orphan")

    def __init__(self, name, owner_id):
        self.name = name
        self.owner_id = owner_id


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Product = db.Column(db.String(200), nullable=False)
    Price = db.Column(db.String(50), nullable=False)
    Zipcode = db.Column(db.String(20), nullable=False)
    delivery_estimate = db.Column(db.String(20), nullable=False)
    shipping_fee = db.Column(db.String(20), nullable=False)
    is_purchased = db.Column(db.Boolean, default=False, nullable=False)
    wishlist_id = db.Column(db.Integer, db.ForeignKey(
        'wishlist.id'), nullable=False)

    def __init__(self, Product, Price, Zipcode, wishlist_id, delivery_estimate, shipping_fee):
        self.Product = Product
        self.Price = Price
        self.Zipcode = Zipcode
        self.wishlist_id = wishlist_id
        self.delivery_estimate = delivery_estimate
        self.shipping_fee = shipping_fee

# =============================================================================
#  Database Initialization
# =============================================================================


def init_db():
    with app.app_context():
        logging.info("Initializing database...")
        logging.info("Dropping all tables.")
        db.drop_all()
        logging.info("Creating all tables.")
        db.create_all()

        logging.info(f"Loading data from {SETUP_FILE}.")
    try:
        with open(SETUP_FILE, 'r') as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Could not load or parse {SETUP_FILE}: {e}")
        return

    # Create user
    user_data = data.get('user')
    if user_data:
        new_user = User(
            username=user_data['username'],
            email=user_data['email']
        )
        new_user.set_password(user_data['password'])
        db.session.add(new_user)
        db.session.commit()
        logging.info(
            f"User with username: '{new_user.username}' password: '{user_data['password']}' email: '{user_data['email']}'")

        # Create wishlist
        wishlist_data = data.get('wishlist')
        if wishlist_data:
            new_wishlist = Wishlist(
                name=wishlist_data['name'],
                owner_id=new_user.id
            )
            db.session.add(new_wishlist)
            db.session.commit()
            logging.info(
                f"Wishlist '{new_wishlist.name}' created for user '{new_user.username}'.")

            # Add products
            products_data = data.get('products', [])
            for prod_data in products_data:
                new_product = Product(
                    Product=prod_data['Product'],
                    Price=prod_data['Price'],
                    Zipcode=prod_data['Zipcode'],
                    delivery_estimate=prod_data['delivery_estimate'],
                    shipping_fee=prod_data['shipping_fee'],
                    wishlist_id=new_wishlist.id
                )
                db.session.add(new_product)
            db.session.commit()
            logging.info(
                f"Added {len(products_data)} products to wishlist '{new_wishlist.name}'.")

    logging.info("Database initialization complete.")

# =============================================================================
#  Authentication Decorator
# =============================================================================


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'detail': 'Bearer token malformed'}), 401

        if not token:
            return jsonify({'detail': 'Not authenticated'}), 401

        try:
            data = jwt.decode(
                token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except jwt.ExpiredSignatureError:
            return jsonify({'detail': 'Token has expired'}), 401
        except (jwt.InvalidTokenError, KeyError):
            return jsonify({'detail': 'Could not validate credentials'}), 401

        if not current_user:
            return jsonify({'detail': 'User not found'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

# =============================================================================
#  Main App Execution
# =============================================================================


with app.app_context():
    init_db()

# =============================================================================
#  Root Route
# =============================================================================


@app.route('/', methods=['GET'])
def root():
    """
    Root endpoint to check if the API is running.
    ---
    responses:
      200:
        description: API is running.
        schema:
          type: object
          properties:
            message:
              type: string
              example: api running
    """
    return jsonify({"message": "api running"}), 200


# =============================================================================
#  Auth Routes
# =============================================================================


@app.route('/auth/register', methods=['POST'])
def register():
    """
    Register a new user.
    ---
    tags:
      - Authentication
    summary: Register a new user
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - username
            - email
            - password
          properties:
            username:
              type: string
              description: The user's username.
              example: testuser
            email:
              type: string
              description: The user's email address.
              example: test@example.com
            password:
              type: string
              description: The user's password.
              example: password123
    responses:
      200:
        description: User registered successfully.
        schema:
          type: object
          properties:
            id:
              type: integer
              description: The user's ID.
            email:
              type: string
              description: The user's email address.
            username:
              type: string
              description: The user's username.
      400:
        description: Email or username already registered.
      422:
        description: Missing or invalid data.
    """

    data = request.get_json()
    if not data or not data.get('email') or not data.get('password') or not data.get('username'):
        return jsonify({"detail": "Missing data"}), 422

    # Basic email validation
    if '@' not in data['email'] or '.' not in data['email']:
        return jsonify({"detail": "Invalid email format"}), 422

    if User.query.filter_by(email=data['email']).first():
        return jsonify({"detail": "Email already registered"}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({"detail": "Username already registered"}), 400

    new_user = User(
        username=data['username'],
        email=data['email']
    )
    new_user.set_password(data['password'])
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"id": new_user.id, "email": new_user.email, "username": new_user.username}), 200


@app.route('/auth/login', methods=['POST'])
def login():
    """
    Log in a user.
    ---
    tags:
      - Authentication
    summary: Log in an existing user
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - email
            - password
          properties:
            email:
              type: string
              description: The user's email address.
              example: test@example.com
            password:
              type: string
              description: The user's password.
              example: password123
    responses:
      200:
        description: Login successful.
        schema:
          type: object
          properties:
            access_token:
              type: string
              description: The JWT access token.
            token_type:
              type: string
              description: The token type.
              example: bearer
      401:
        description: Incorrect email or password.
    """
    data = request.json
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"detail": "Email or password not provided"}), 400

    user = User.query.filter_by(email=data['email']).first()

    if not user or not user.check_password(data['password']):
        return jsonify({"detail": "Incorrect email or password"}), 401

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.now(timezone.utc) + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({'access_token': token, 'token_type': 'bearer'})

# =============================================================================
#  Wishlist Routes
# =============================================================================


@app.route('/wishlists', methods=['POST'])
@token_required
def create_wishlist(current_user):
    """
    Create a new wishlist.
    ---
    tags:
      - Wishlists
    summary: Create a new wishlist for the authenticated user
    security:
      - bearerAuth: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - name
          properties:
            name:
              type: string
              description: The name of the wishlist.
              example: My Favorite Books
    responses:
      200:
        description: Wishlist created successfully.
        schema:
          type: object
          properties:
            id:
              type: integer
              description: The wishlist ID.
            name:
              type: string
              description: The name of the wishlist.
            owner_id:
              type: integer
              description: The ID of the user who owns the wishlist.
      422:
        description: Missing name.
    """
    data = request.get_json()
    if not data or not data.get('name'):
        return jsonify({"detail": "Missing name"}), 422

    new_wishlist = Wishlist(
        name=data['name'],
        owner_id=current_user.id
    )
    db.session.add(new_wishlist)
    db.session.commit()

    return jsonify({"id": new_wishlist.id, "name": new_wishlist.name, "owner_id": new_wishlist.owner_id}), 200


@app.route('/wishlists', methods=['GET'])
@token_required
def get_wishlists(current_user):
    """
    Get all wishlists for the current user.
    ---
    tags:
      - Wishlists
    summary: Get all wishlists for the authenticated user
    security:
      - bearerAuth: []
    responses:
      200:
        description: A list of wishlists.
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
              name:
                type: string
              owner_id:
                type: integer
    """
    wishlists = Wishlist.query.filter_by(owner_id=current_user.id).all()
    output = []
    for wishlist in wishlists:
        output.append({
            "id": wishlist.id,
            "name": wishlist.name,
            "owner_id": wishlist.owner_id
        })
    return jsonify(output), 200


# =============================================================================
#  Product Routes
# =============================================================================

@app.route('/wishlists/<int:wishlist_id>/products', methods=['POST'])
@token_required
def add_product_to_wishlist(current_user, wishlist_id):
    """
    Add a product to a wishlist.
    ---
    tags:
      - Products
    summary: Add a new product to a specific wishlist
    security:
      - bearerAuth: []
    parameters:
      - name: wishlist_id
        in: path
        type: integer
        required: true
        description: The ID of the wishlist to add the product to.
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - Product
            - Price
            - Zipcode
            - delivery_estimate
            - shipping_fee
          properties:
            Product:
              type: string
              description: The name of the product.
              example: The Great Gatsby
            Price:
              type: string
              description: The price of the product.
              example: "15.99"
            Zipcode:
              type: string
              description: The zipcode for delivery.
              example: "90210"
            delivery_estimate:
              type: string
              description: The estimated delivery time.
              example: "5 days"
            shipping_fee:
              type: string
              description: The shipping fee.
              example: "2.00"
    responses:
      200:
        description: Product added successfully.
        schema:
          type: object
          properties:
            id:
              type: integer
            Product:
              type: string
            Price:
              type: string
            is_purchased:
              type: boolean
            delivery_estimate:
              type: string
            wishlist_id:
              type: integer
      404:
        description: Wishlist not found.
      422:
        description: Missing product data.
    """
    wishlist = Wishlist.query.filter_by(
        id=wishlist_id, owner_id=current_user.id).first()
    if not wishlist:
        return jsonify({"detail": "Wishlist not found"}), 404

    data = request.get_json()
    if not data or not data.get('Product') or not data.get('Price') or not data.get('Zipcode'):
        return jsonify({"detail": "Missing product data"}), 422

    new_product = Product(
        Product=data['Product'],
        Price=data['Price'],
        Zipcode=data['Zipcode'],
        delivery_estimate=data['delivery_estimate'],
        shipping_fee=data['shipping_fee'],
        wishlist_id=wishlist.id
    )
    db.session.add(new_product)
    db.session.commit()

    return jsonify({
        "id": new_product.id,
        "Product": new_product.Product,
        "Price": new_product.Price,
        "is_purchased": new_product.is_purchased,
        "delivery_estimate": new_product.delivery_estimate,
        "wishlist_id": new_product.wishlist_id
    }), 200


@app.route('/wishlists/<int:wishlist_id>/products', methods=['GET'])
@token_required
def get_products_from_wishlist(current_user, wishlist_id):
    """
    Get all products from a wishlist.
    ---
    tags:
      - Products
    summary: Get all products from a specific wishlist
    security:
      - bearerAuth: []
    parameters:
      - name: wishlist_id
        in: path
        type: integer
        required: true
        description: The ID of the wishlist.
    responses:
      200:
        description: A list of products.
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
              Product:
                type: string
              Price:
                type: string
              is_purchased:
                type: boolean
              delivery_estimate:
                type: string
              wishlist_id:
                type: integer
      404:
        description: Wishlist not found.
    """
    wishlist = Wishlist.query.filter_by(
        id=wishlist_id, owner_id=current_user.id).first()
    if not wishlist:
        return jsonify({"detail": "Wishlist not found"}), 404

    products = Product.query.filter_by(wishlist_id=wishlist.id).all()
    output = []
    for product in products:
        output.append({
            "id": product.id,
            "Product": product.Product,
            "Price": product.Price,
            "is_purchased": product.is_purchased,
            "delivery_estimate": product.delivery_estimate,
            "wishlist_id": product.wishlist_id
        })
    return jsonify(output), 200


@app.route('/products/<int:product_id>', methods=['PUT'])
@token_required
def update_product(current_user, product_id):
    """
    Update a product's price.
    ---
    tags:
      - Products
    summary: Update a product's price
    security:
      - bearerAuth: []
    parameters:
      - name: product_id
        in: path
        type: integer
        required: true
        description: The ID of the product to update.
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            Price:
              type: string
              description: The new price of the product.
              example: "20.00"
    responses:
      200:
        description: Product updated successfully.
        schema:
          type: object
          properties:
            id:
              type: integer
            Product:
              type: string
            Price:
              type: string
            is_purchased:
              type: boolean
            delivery_estimate:
              type: string
            wishlist_id:
              type: integer
      404:
        description: Product not found.
    """
    product = db.session.query(Product).filter(
        Product.id == product_id,
        Product.wishlist_id.in_(db.session.query(Wishlist.id).filter(
            Wishlist.owner_id == current_user.id))
    ).first()
    if not product:
        return jsonify({"detail": "Product not found"}), 404

    data = request.get_json()
    if 'Price' in data:
        product.Price = data['Price']

    db.session.commit()
    return jsonify({
        "id": product.id,
        "Product": product.Product,
        "Price": product.Price,
        "is_purchased": product.is_purchased,
        "delivery_estimate": product.delivery_estimate,
        "wishlist_id": product.wishlist_id
    }), 200


@app.route('/products/<int:product_id>', methods=['DELETE'])
@token_required
def delete_product(current_user, product_id):
    """
    Delete a product.
    ---
    tags:
      - Products
    summary: Delete a product
    security:
      - bearerAuth: []
    parameters:
      - name: product_id
        in: path
        type: integer
        required: true
        description: The ID of the product to delete.
    responses:
      204:
        description: Product deleted successfully.
      404:
        description: Product not found.
    """
    product = db.session.query(Product).filter(
        Product.id == product_id,
        Product.wishlist_id.in_(db.session.query(Wishlist.id).filter(
            Wishlist.owner_id == current_user.id))
    ).first()
    if not product:
        return jsonify({"detail": "Product not found"}), 404

    db.session.delete(product)
    db.session.commit()
    return '', 204


if __name__ == '__main__':
    logging.info("Starting Flask server...")
    logging.info("API running at http://127.0.0.1:8000/")
    app.run(debug=True, port=8000)
