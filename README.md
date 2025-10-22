# Wishlist API

This is a simple Wishlist API built with Flask.

## How to Run

1.  **Create and activate a virtual environment:**

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

2.  **Install the dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the application:**

    ```bash
    python app.py
    ```

The API will be running at `http://127.0.0.1:8000/`.

## Initial Setup Data

When the application starts, it automatically creates a default user, a wishlist, and several products based on the `setup.json` file. This is useful for testing and demonstration purposes.

-   **Default User:**
    -   email: `projeto@example.com`
    -   password: `Senha123!`

-   **Default Wishlist:**
    -   name: `projeto_final`

-   **Default Products:**
    -   Apple iPhone 17 Pro Max 512GB Laranja-cosmico
    -   Apple Watch se gps Caixa prateada de alumínio – 44 mm Pulseira esportiva denim – p/m
    -   Apple MacBook Air 13, M3, cpu de 8 núcleos, gpu de 8 núcleos, 24GB ram, 512GB ssd - Meia-noite

## Swagger Documentation

To access the Swagger documentation, navigate to the following URL in your browser:

[http://127.0.0.1:8000/apidocs/](http://127.0.0.1:8000/apidocs/)