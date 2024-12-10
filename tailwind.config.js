/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./online/templates/**/*.{html,js}"],
  theme: {
    extend: {},
  },
  plugins: [
    require('@tailwindcss/line-clamp'),
  ],
};

