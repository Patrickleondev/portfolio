import { defineConfig } from 'vite'

export default defineConfig({
    base: '/portfolio/', // Repo name is 'portfolio'
    build: {
        rollupOptions: {
            input: {
                main: 'index.html',
                about: 'about.html',
                expertise: 'expertise.html',
                projects: 'projects.html',
            },
        },
    },
})
