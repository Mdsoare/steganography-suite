import globals from "globals";

export default [
    {
        files: ["assets/js/**/*.js"],
        languageOptions: {
            ecmaVersion: 2021,
            sourceType: "script",
            globals: {
                ...globals.browser,
            },
        },
        rules: {
            "no-undef": "error",
            "no-unused-vars": "warn",
            "semi": ["error", "always"],
        },
    },
];