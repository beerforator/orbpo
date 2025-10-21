const inquirer = require('inquirer');
const { register, login, recoverPassword, readDb, simulateSqlInjection, generateSecureKey, initiatePasswordRecovery, finalizePasswordReset } = require('./auth');

const MAX_RECOVERY_ATTEMPTS = 3;

const promptRegister = async () => {
    const answers = await inquirer.prompt([
        { type: 'input', name: 'email', message: 'Введите ваш email:' },
        { type: 'password', name: 'password', message: 'Введите пароль (мин. 8 символов, верхний/нижний регистр, цифры):', mask: '*' },
        { type: 'input', name: 'q1', message: 'Контрольный вопрос 1: [В каком городе вы родились?]' },
        { type: 'password', name: 'a1', message: 'Ответ на вопрос 1:', mask: '*' },
        { type: 'input', name: 'q2', message: 'Контрольный вопрос 2: [Кличка вашего первого домашнего животного?]' },
        { type: 'password', name: 'a2', message: 'Ответ на вопрос 2:', mask: '*' },
    ]);

    const questions = [
        { question: answers.q1 ? answers.q1 : "В каком городе вы родились?", answer: answers.a1 },
        { question: answers.q2 ? answers.q2 : "Кличка вашего первого домашнего животного?", answer: answers.a2 },
    ];

    register(answers.email, answers.password, questions);
};

const promptInitiateRecovery = async () => {
    console.log('\n--- Восстановление доступа (Шаг 1 из 2) ---');
    const { email } = await inquirer.prompt([{ type: 'input', name: 'email', message: 'Введите ваш email:' }]);

    const db = readDb();
    const user = db.users[email];
    if (!user) {
        console.error('Пользователь не найден.');
        return;
    }

    const userAnswers = [];
    for (const qa of user.secretQuestions) {
        const { answer } = await inquirer.prompt([{ type: 'password', name: 'answer', message: qa.question, mask: '*' }]);
        userAnswers.push(answer);
    }

    const token = initiatePasswordRecovery(email, userAnswers);

    if (token) {
        console.log('\nОтветы верны! Ваш одноразовый токен для сброса пароля:');
        console.log(`\n${token}\n`);
        console.log('Теперь выберите в меню "Завершить сброс пароля" и используйте его.');
    } else {
        console.error('\nНеверные ответы на контрольные вопросы.');
    }
};

const promptFinalizeReset = async () => {
    console.log('\n--- Завершение сброса пароля (Шаг 2 из 2) ---');
    const answers = await inquirer.prompt([
        { type: 'input', name: 'email', message: 'Ваш email:' },
        { type: 'input', name: 'token', message: 'Одноразовый токен сброса:' },
        { type: 'password', name: 'newPassword', message: 'Ваш новый пароль:', mask: '*' },
    ]);

    if (finalizePasswordReset(answers.email, answers.token, answers.newPassword)) {
        console.log('\nПароль успешно изменен!');
    } else {
        console.log('\nНе удалось сбросить пароль. Попробуйте начать сначала.');
    }
};

const promptLogin = async () => {
    const answers = await inquirer.prompt([
        { type: 'input', name: 'email', message: 'Email:' },
        { type: 'password', name: 'password', message: 'Пароль:', mask: '*' },
    ]);

    if (login(answers.email, answers.password)) {
        console.log('\nУспешный вход в систему!');
    } else {
        console.error('\nНеверный email или пароль.');
    }
};

const promptRecover = async () => {
    const { email } = await inquirer.prompt([{ type: 'input', name: 'email', message: 'Введите ваш email для восстановления:' }]);

    const db = readDb();
    const user = db.users[email];

    if (!user) {
        console.error('Пользователь с таким email не найден.');
        return;
    }

    let attempts = MAX_RECOVERY_ATTEMPTS;
    let isSuccess = false;

    while (attempts > 0) {
        console.log(`\nУ вас осталось попыток: ${attempts}`);

        const userAnswers = [];
        for (const qa of user.secretQuestions) {
            const { answer } = await inquirer.prompt([{ type: 'password', name: 'answer', message: qa.question, mask: '*' }]);
            userAnswers.push(answer);
        }

        const { newPassword } = await inquirer.prompt([{
            type: 'password',
            name: 'newPassword',
            message: 'Введите новый пароль:',
            mask: '*'
        }]);

        if (recoverPassword(email, userAnswers, newPassword)) {
            console.log('\nПароль успешно сброшен!');
            isSuccess = true;
            break;
        } else {
            console.error('Один или несколько ответов неверны.');
            attempts--;
        }
    }

    if (!isSuccess) {
        console.error('\nПревышено количество попыток. Восстановление заблокировано.');
    }
};

const promptVulnerabilityDemos = async () => {
    const { demo } = await inquirer.prompt([{
        type: 'list',
        name: 'demo',
        message: 'Выберите демонстрацию:',
        choices: ['SQL-инъекция', 'Вернуться в главное меню'],
    }]);

    if (demo === 'SQL-инъекция') {
        const { userInput } = await inquirer.prompt([{
            type: 'input',
            name: 'userInput',
            message: "Введите имя пользователя для входа (попробуйте ввести: admin' --):"
        }]);
        simulateSqlInjection(userInput);
    }
};

const mainMenu = async () => {
    const { action } = await inquirer.prompt([{
        type: 'list',
        name: 'action',
        message: 'Выберите действие:',
        choices: ['Регистрация', 'Вход', 'Восстановление доступа (Шаг 1)', 'Завершить сброс пароля (Шаг 2)', 'Демонстрация уязвимостей', 'Выход'],
    }]);

    switch (action) {
        case 'Регистрация':
            await promptRegister();
            break;
        case 'Вход':
            await promptLogin();
            break;
        case 'Восстановление доступа (Шаг 1)':
            await promptInitiateRecovery();
            break;
        case 'Завершить сброс пароля (Шаг 2)':
            await promptFinalizeReset();
            break;
        case 'Демонстрация уязвимостей':
            await promptVulnerabilityDemos();
            break;
        case 'Выход':
            return;
    }

    mainMenu();
};

console.log('Добро пожаловать в безопасную систему аутентификации!');
mainMenu();