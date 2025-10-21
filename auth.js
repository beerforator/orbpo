const fs = require('fs');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const DB_FILE = './db.json';
const INTEGRITY_FILE = './db.integrity';
const SALT_ROUNDS = 10;

// ЗАДАНИЕ №5
function generateSecureKey(length = 16) {
    console.log(`\n[+] Генерируем криптографически стойкий ключ длиной ${length} байт...`);
    const key = crypto.randomBytes(length).toString('hex');
    return key;
}

const initiatePasswordRecovery = (email, answers) => {
    const sanitizedEmail = sanitizeInput(email);
    const db = readDb();
    const user = db.users[sanitizedEmail];

    if (!user) {
        console.error('Пользователь не найден.');
        return null;
    }

    if (user.secretQuestions.length !== answers.length) return null;

    for (let i = 0; i < user.secretQuestions.length; i++) {
        const providedAnswer = sanitizeInput(answers[i]).toLowerCase();
        if (!bcrypt.compareSync(providedAnswer, user.secretQuestions[i].answerHash)) {
            return null;
        }
    }

    const resetToken = generateSecureKey(16);
    user.resetToken = resetToken; 
    writeDb(db);

    return resetToken;
};

const finalizePasswordReset = (email, token, newPassword) => {
    const sanitizedEmail = sanitizeInput(email);
    const sanitizedToken = sanitizeInput(token);

    const db = readDb();
    const user = db.users[sanitizedEmail];

    if (!user || !user.resetToken || user.resetToken !== sanitizedToken) {
        console.error('Неверный email или токен сброса.');
        return false;
    }

    if (!isStrongPassword(newPassword)) {
        console.error('Ошибка: Новый пароль не соответствует требованиям безопасности.');
        return false;
    }

    user.passwordHash = bcrypt.hashSync(newPassword, SALT_ROUNDS);
    delete user.resetToken;
    writeDb(db);

    return true;
};

// ЗАДАНИЕ №4
function sanitizeInput(input) {
    if (typeof input !== 'string') return input;

    const sanitized = input.replace(/<script\b[^>]*>([\s\S]*?)<\/script>/gi, '');

    if (input !== sanitized) {
        console.log(`[!] Обнаружена и удалена потенциально опасная конструкция XSS. Результат: "${sanitized}"`);
    }
    return sanitized;
}

// ЗАДАНИЕ №3
function calculateHash(text) {
    return crypto.createHash('sha256').update(text).digest('hex');
}

const verifyDbIntegrity = () => {
    if (!fs.existsSync(DB_FILE) || !fs.existsSync(INTEGRITY_FILE)) {
        return true;
    }

    const dbContent = fs.readFileSync(DB_FILE, 'utf8');
    const storedHash = fs.readFileSync(INTEGRITY_FILE, 'utf8');

    const currentHash = calculateHash(dbContent);

    if (currentHash !== storedHash) {
        throw new Error('КРИТИЧЕСКАЯ ОШИБКА: Целостность базы данных нарушена! Файл db.json был изменен извне.');
    }

    return true;
};

const readDb = () => {
    try {
        verifyDbIntegrity();
    } catch (e) {
        console.error(e.message);
        process.exit(1);
    }

    try {
        if (!fs.existsSync(DB_FILE)) return { users: {} };
        const data = fs.readFileSync(DB_FILE);
        return JSON.parse(data);
    } catch (error) {
        return { users: {} };
    }
};

const writeDb = (data) => {
    const stringifiedData = JSON.stringify(data, null, 2);
    fs.writeFileSync(DB_FILE, stringifiedData);

    const newHash = calculateHash(stringifiedData);
    fs.writeFileSync(INTEGRITY_FILE, newHash);
};

// ЗАДАНИЕ 1
const isStrongPassword = (password) => {
    const sanitizedPassword = sanitizeInput(password);

    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(sanitizedPassword);
    const hasLowerCase = /[a-z]/.test(sanitizedPassword);
    const hasNumbers = /\d/.test(sanitizedPassword);

    return sanitizedPassword.length >= minLength && hasUpperCase && hasLowerCase && hasNumbers;
};

const register = (email, password, questions) => {
    const db = readDb();
    const sanitizedEmail = sanitizeInput(email);

    if (db.users[sanitizedEmail]) {
        console.error('Ошибка: Пользователь с таким email уже существует.');
        return false;
    }

    if (!isStrongPassword(password)) {
        console.error('Ошибка: Пароль не соответствует требованиям безопасности.');
        return false;
    }

    const passwordHash = bcrypt.hashSync(password, SALT_ROUNDS);

    const secretQuestions = questions.map(({ question, answer }) => ({
        question: sanitizeInput(question),
        answerHash: bcrypt.hashSync(sanitizeInput(answer).toLowerCase(), SALT_ROUNDS),
    }));

    db.users[sanitizedEmail] = {
        passwordHash,
        secretQuestions,
    };

    writeDb(db);
    console.log('Пользователь успешно зарегистрирован!');
    return true;
};

const login = (email, password) => {
    const db = readDb();
    const sanitizedEmail = sanitizeInput(email);
    const user = db.users[sanitizedEmail];

    if (!user) {
        return false;
    }

    return bcrypt.compareSync(password, user.passwordHash);
};

const recoverPassword = (email, answers, newPassword) => {
    const db = readDb();
    const sanitizedEmail = sanitizeInput(email);
    const user = db.users[sanitizedEmail];

    if (!user) {
        console.error('Пользователь не найден.');
        return false;
    }

    if (user.secretQuestions.length !== answers.length) return false;

    for (let i = 0; i < user.secretQuestions.length; i++) {
        const providedAnswer = answers[i].toLowerCase();
        const { answerHash } = user.secretQuestions[i];
        if (!bcrypt.compareSync(providedAnswer, answerHash)) {
            return false;
        }
    }

    if (!isStrongPassword(newPassword)) {
        console.error('Ошибка: Новый пароль не соответствует требованиям безопасности.');
        return false;
    }

    user.passwordHash = bcrypt.hashSync(newPassword, SALT_ROUNDS);
    writeDb(db);

    return true;
};

// ЗАДАНИЕ №2
const simulateSqlInjection = (userInput) => {
    console.log(`\n--- Симуляция SQL-инъекции ---`);
    console.log(`Пользователь ввел: "${userInput}"`);

    const baseQuery = "SELECT * FROM users WHERE login = '";

    const vulnerableQuery = baseQuery + userInput + "';";

    console.log(`\nИтоговый SQL-запрос, который будет выполнен в базе данных:`);
    console.log(vulnerableQuery);

    if (userInput.includes('--')) {
        console.log("\n❗️ Уязвимость сработала! Часть запроса после '--' была закомментирована.");
        console.log("Такой запрос может вернуть данные всех пользователей, обойдя проверку пароля.");
    } else {
        console.log("\nВ данном случае ввод безопасен, запрос будет искать пользователя с таким именем.");
    }
    console.log(`--- Конец симуляции ---`);
};

module.exports = {
    register,
    login,
    recoverPassword,
    readDb,
    simulateSqlInjection,
    generateSecureKey,
    initiatePasswordRecovery,
    finalizePasswordReset
};