# Dokumentasi API Sistem Manajemen Gudang

## Autentikasi

Semua endpoint API memerlukan autentikasi menggunakan session login.

### Login

```
POST /login
```

Request body:
```json
{
    "username": "string",
    "password": "string"
}
```

Response success (200):
```json
{
    "message": "Login berhasil",
    "user": {
        "username": "string",
        "name": "string",
        "role": "string"
    }
}
```

## Endpoint Inventory

### Get All Items

```
GET /api/inventory
```

Response success (200):
```json
[
    {
        "id": "ITEM001",
        "name": "string",
        "quantity": 0,
        "category": "string",
        "added_by": "string",
        "last_update": "datetime string"
    }
]
```

### Add New Item

```
POST /api/inventory
```

Request body:
```json
{
    "item_id": "string",
    "name": "string",
    "quantity": 0,
    "category": "string"
}
```

Response success (201):
```json
{
    "id": "string",
    "name": "string",
    "quantity": 0,
    "category": "string",
    "added_by": "string",
    "last_update": "datetime string"
}
```

## Endpoint Transactions

### Get All Transactions

```
GET /api/transactions
```

Query parameters:
- type: string (optional, "masuk" atau "keluar")

Response success (200):
```json
[
    {
        "id": 0,
        "type": "string",
        "item_id": "string",
        "quantity": 0,
        "user": "string",
        "timestamp": "datetime string",
        "notes": "string"
    }
]
```

### Add Incoming Transaction

```
POST /api/transactions/incoming
```

Request body:
```json
{
    "item_id": "string",
    "quantity": 0,
    "notes": "string (optional)"
}
```

Response success (201):
```json
{
    "id": 0,
    "type": "masuk",
    "item_id": "string",
    "quantity": 0,
    "user": "string",
    "timestamp": "datetime string",
    "notes": "string"
}
```

## Endpoint Users

### Get All Users (Admin Only)

```
GET /api/users
```

Response success (200):
```json
[
    {
        "username": "string",
        "name": "string",
        "role": "string"
    }
]
```

### Add New User (Admin Only)

```
POST /api/users
```

Request body:
```json
{
    "username": "string",
    "password": "string",
    "name": "string",
    "role": "string"
}
```

Response success (201):
```json
{
    "username": "string",
    "name": "string",
    "role": "string"
}
```

## Error Responses

Semua endpoint dapat mengembalikan response error berikut:

400 Bad Request:
```json
{
    "error": "Pesan error validasi"
}
```

401 Unauthorized:
```json
{
    "error": "Akses ditolak. Silakan login terlebih dahulu."
}
```

403 Forbidden:
```json
{
    "error": "Role tidak memiliki akses ke resource ini"
}
```

404 Not Found:
```json
{
    "error": "Resource tidak ditemukan"
}
```

500 Internal Server Error:
```json
{
    "error": "Pesan error internal server"
}
``` 