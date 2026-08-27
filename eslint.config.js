import globals from "globals";

export default [
  {
    files: ["assets/js/**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        ...globals.browser,
      },
    },
    rules: {
      "no-undef": "error",
      "no-unused-vars": ["warn", { "argsIgnorePattern": "^_" }],
      "no-eval": "error",
      "no-implied-eval": "error",
      "semi": ["error", "always"],
      "quotes": ["warn", "single"],
      "eqeqeq": ["error", "always"],
    },
  },
];