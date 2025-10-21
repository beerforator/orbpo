// task1.js

/**
 * Проверяет пароль на соответствие требованиям безопасности.
 * @param {string} password - Пароль для проверки.
 * @returns {boolean} - true, если пароль надежный, иначе false.
 */
function isStrongPassword(password) {
    // 1. Проверка минимальной длины
    const minLength = 8;
    if (password.length < minLength) {
        console.log(` -> Ошибка: Пароль слишком короткий (менее ${minLength} символов).`);
        return false;
    }

    // 2. Проверка на наличие букв в нижнем регистре
    const hasLowerCase = /[a-z]/.test(password);
    if (!hasLowerCase) {
        console.log(" -> Ошибка: Пароль должен содержать хотя бы одну букву в нижнем регистре.");
        return false;
    }

    // 3. Проверка на наличие букв в верхнем регистре
    const hasUpperCase = /[A-Z]/.test(password);
    if (!hasUpperCase) {
        console.log(" -> Ошибка: Пароль должен содержать хотя бы одну букву в верхнем регистре.");
        return false;
    }

    // 4. Проверка на наличие цифр
    const hasNumbers = /\d/.test(password); // \d - это любой цифровой символ
    if (!hasNumbers) {
        console.log(" -> Ошибка: Пароль должен содержать хотя бы одну цифру.");
        return false;
    }

    // Если все проверки пройдены
    return true;
}

// --- Демонстрация работы функции ---
function main() {
    console.log("--- Проверка надежности паролей ---");

    const passwordsToTest = [
        "password",      // Слишком простой, нет верхнего регистра и цифр
        "short",         // Слишком короткий
        "PASSWORD123",   // Нет нижнего регистра
        "Password",      // Нет цифр
        "GoodPassword123"// Соответствует всем требованиям
    ];

    passwordsToTest.forEach(pass => {
        console.log(`\nПроверяем пароль: "${pass}"`);
        const isStrong = isStrongPassword(pass);
        if (isStrong) {
            console.log(" -> Результат: Пароль надежный. ✅");
        } else {
            console.log(" -> Результат: Пароль слабый. ❌");
        }
    });
}

// Запускаем демонстрацию
main();