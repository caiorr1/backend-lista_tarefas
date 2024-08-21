const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors()); // Habilita o CORS para todas as origens
const PORT = 3000;

const db = new sqlite3.Database('banco-de-dados.db');

// Criar a tabela 'tarefas' no banco de dados
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS tarefas (id INTEGER PRIMARY KEY, tarefa TEXT)");
});

// Criar a tabela 'usuarios' no banco de dados
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY, username TEXT UNIQUE, email TEXT UNIQUE, password TEXT, role TEXT)");
});

app.use(express.json());

// Middleware para verificar e decodificar o token JWT
const verificarToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(403).json({ error: 'Nenhum token fornecido.' });
    }
    jwt.verify(token.split(' ')[1], 'secreto', (err, decoded) => {
        if (err) {
            return res.status(500).json({ error: 'Falha ao autenticar o token.' });
        }
        req.userId = decoded.id;
        req.userRole = decoded.role;
        next();
    });
};

// Rota para adicionar uma nova tarefa
app.post('/tarefas', verificarToken, (req, res) => {
    const { tarefa } = req.body;
    db.run("INSERT INTO tarefas (tarefa) VALUES (?)", [tarefa], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(201).json({ id: this.lastID, tarefa });
    });
});

// Rota para obter todas as tarefas
app.get('/tarefas', verificarToken, (req, res) => {
    db.all("SELECT * FROM tarefas", [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(200).json(rows);
    });
});

// Rota para obter uma tarefa específica
app.get('/tarefas/:id', verificarToken, (req, res) => {
    const { id } = req.params;
    db.get("SELECT * FROM tarefas WHERE id = ?", [id], (err, row) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (row) {
            res.status(200).json(row);
        } else {
            res.status(404).json({ error: 'Tarefa não encontrada!' });
        }
    });
});

// Rota para editar uma tarefa existente
app.put('/tarefas/:id', verificarToken, (req, res) => {
    const { id } = req.params;
    const { tarefa } = req.body;
    db.run("UPDATE tarefas SET tarefa = ? WHERE id = ?", [tarefa, id], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (this.changes) {
            res.status(200).json({ message: 'Tarefa atualizada com sucesso!' });
        } else {
            res.status(404).json({ error: 'Tarefa não encontrada!' });
        }
    });
});

// Rota para excluir uma tarefa
app.delete('/tarefas/:id', verificarToken, (req, res) => {
    const { id } = req.params;
    db.run("DELETE FROM tarefas WHERE id = ?", [id], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (this.changes) {
            res.status(200).json({ message: 'Tarefa removida com sucesso!' });
        } else {
            res.status(404).json({ error: 'Tarefa não encontrada!' });
        }
    });
});

// Rota para registrar um novo usuário
app.post('/registro', async (req, res) => {
    const { username, email, password, role } = req.body;
    try {
        const usuarioExistente = await buscarUsuario(username);
        if (usuarioExistente) {
            return res.status(400).json({ error: 'Usuário já registrado' });
        }

        const emailExistente = await buscarUsuarioPorEmail(email);
        if (emailExistente) {
            return res.status(400).json({ error: 'Email já registrado' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await criarUsuario(username, email, hashedPassword, role);
        res.status(201).json({ message: 'Usuário registrado com sucesso' });
    } catch (error) {
        console.error('Erro no registro:', error);
        res.status(500).json({ error: 'Erro no registro de usuário' });
    }
});

// Rota para autenticar o usuário e gerar token JWT
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const usuario = await buscarUsuario(username);
        if (!usuario) {
            return res.status(401).json({ error: 'Usuário não encontrado' });
        }
        const senhaValida = await bcrypt.compare(password, usuario.password);
        if (!senhaValida) {
            return res.status(401).json({ error: 'Senha incorreta' });
        }
        const token = jwt.sign({ id: usuario.id, username: usuario.username, role: usuario.role }, 'secreto', { expiresIn: '1h' });
        res.status(200).json({ token });
    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ error: 'Erro no login de usuário' });
    }
});

// Rota para iniciar o processo de recuperação de senha
app.post('/recuperar-senha', async (req, res) => {
    const { email } = req.body;

    try {
        const usuario = await buscarUsuarioPorEmail(email);
        if (!usuario) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        // Aqui você pode gerar um token de redefinição de senha e enviar para o e-mail
        const resetToken = jwt.sign({ id: usuario.id }, 'secreto', { expiresIn: '15m' });

        // Implementar a lógica de envio do e-mail com o token
        // ...

        res.status(200).json({ message: 'Instruções de recuperação de senha enviadas para o e-mail cadastrado.' });
    } catch (error) {
        console.error('Erro ao recuperar senha:', error);
        res.status(500).json({ error: 'Erro ao iniciar o processo de recuperação de senha.' });
    }
});

// Rota para redefinir a senha usando o token
app.post('/redefinir-senha', async (req, res) => {
    const { token, newPassword } = req.body;

    try {
        const decoded = jwt.verify(token, 'secreto');
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        db.run('UPDATE usuarios SET password = ? WHERE id = ?', [hashedPassword, decoded.id], function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.status(200).json({ message: 'Senha alterada com sucesso!' });
        });
    } catch (error) {
        console.error('Erro ao redefinir senha:', error);
        res.status(500).json({ error: 'Token inválido ou expirado.' });
    }
});

// Rota para deletar um usuário
app.delete('/usuarios/:id', verificarToken, (req, res) => {
    const { id } = req.params;

    // Verifique se o usuário tem permissão (por exemplo, se é administrador)
    if (req.userRole !== 'admin') {
        return res.status(403).json({ error: 'Acesso negado. Apenas administradores podem deletar usuários.' });
    }

    db.run("DELETE FROM usuarios WHERE id = ?", [id], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (this.changes) {
            res.status(200).json({ message: 'Usuário deletado com sucesso!' });
        } else {
            res.status(404).json({ error: 'Usuário não encontrado!' });
        }
    });
});

// Rota para alterar o role de um usuário
app.put('/usuarios/:id/role', verificarToken, (req, res) => {
    const { id } = req.params;
    const { role } = req.body;

    // Verifique se o usuário tem permissão para alterar roles (por exemplo, se é administrador)
    if (req.userRole !== 'admin') {
        return res.status(403).json({ error: 'Acesso negado. Apenas administradores podem alterar o role de usuários.' });
    }

    db.run("UPDATE usuarios SET role = ? WHERE id = ?", [role, id], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (this.changes) {
            res.status(200).json({ message: 'Role do usuário alterado com sucesso!' });
        } else {
            res.status(404).json({ error: 'Usuário não encontrado!' });
        }
    });
});

// Função para buscar usuário no banco de dados por nome de usuário
const buscarUsuario = (username) => {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM usuarios WHERE username = ?', [username], (err, row) => {
            if (err) {
                reject(err);
            }
            resolve(row);
        });
    });
};

// Função para buscar usuário no banco de dados por e-mail
const buscarUsuarioPorEmail = (email) => {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM usuarios WHERE email = ?', [email], (err, row) => {
            if (err) {
                reject(err);
            }
            resolve(row);
        });
    });
};

// Função para criar um novo usuário no banco de dados
const criarUsuario = (username, email, password, role) => {
    return new Promise((resolve, reject) => {
        db.run('INSERT INTO usuarios (username, email, password, role) VALUES (?, ?, ?, ?)', [username, email, password, role], (err) => {
            if (err) {
                reject(err);
            }
            resolve();
        });
    });
};

// Inicie o servidor Express
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta http://localhost:${PORT}`);
});
