import json
from werkzeug.security import generate_password_hash

username = input("Digite o nome de usuário: ")
password = input("Digite a senha: ")

hashed_password = generate_password_hash(password)

#load existent users
try:
    with open('json/users.json', 'r', encoding='utf-8') as f:
        users = json.load(f)
except FileNotFoundError:
    users = []

used_ids = {u.get("id", 0) for u in users}

for i in range(1, 1000):
    if i not in used_ids:
        new_id = i
        break

#register a new user
users.append({
    "id": new_id,
    "username": username,
    "password": hashed_password
})

#save
with open('json/users.json', 'w', encoding='utf-8') as f:
    json.dump(users, f, indent=4, ensure_ascii=False)

print(f"Usuário '{username}' registrado com sucesso.")
