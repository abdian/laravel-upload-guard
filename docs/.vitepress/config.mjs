import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Laravel Safeguard',
  description: 'Secure file upload validation for Laravel',

  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/' },
      { text: 'API', link: '/api/' }
    ],

    sidebar: {
      '/guide/': [
        {
          text: 'Introduction',
          items: [
            { text: 'What is Safeguard?', link: '/guide/' },
            { text: 'Installation', link: '/guide/installation' },
            { text: 'Quick Start', link: '/guide/quick-start' }
          ]
        },
        {
          text: 'Usage',
          items: [
            { text: 'Basic Usage', link: '/guide/usage' },
            { text: 'Validation Rules', link: '/guide/rules' },
            { text: 'Configuration', link: '/guide/config' }
          ]
        },
        {
          text: 'Security',
          items: [
            { text: 'Security Features', link: '/guide/security' }
          ]
        }
      ],
      '/api/': [
        {
          text: 'API Reference',
          items: [
            { text: 'Rules', link: '/api/' },
            { text: 'Configuration', link: '/api/config' }
          ]
        }
      ]
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/abdian/laravel-upload-guard' }
    ]
  }
})
