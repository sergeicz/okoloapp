// Yandex.Metrika Analytics
(function(m,e,t,r,i,k,a){
    m[i]=m[i]||function(){(m[i].a=m[i].a||[]).push(arguments)};
    m[i].l=1*new Date();
    for (var j = 0; j < document.scripts.length; j++) {if (document.scripts[j].src === r) { return; }}
    k=e.createElement(t),a=e.getElementsByTagName(t)[0],k.async=1,k.src=r,a.parentNode.insertBefore(k,a)
})(window, document,'script','https://mc.yandex.ru/metrika/tag.js?id=106803279', 'ym');

ym(106803279, 'init', {
    ssr: true,
    webvisor: true,
    clickmap: true,
    ecommerce: "dataLayer",
    referrer: document.referrer,
    url: location.href,
    accurateTrackBounce: true,
    trackLinks: true
});

// Analytics Helper Functions
window.metrikaTrack = {
    // Переход по партнерской ссылке
    partnerClick: function(partnerTitle, category, url) {
        ym(106803279, 'reachGoal', 'partner_click', {
            partner: partnerTitle,
            category: category,
            url: url
        });
        console.log('[Metrika] Partner click:', partnerTitle);
    },

    // Просмотр образовательного материала
    educationView: function(title, videoUrl) {
        ym(106803279, 'reachGoal', 'education_view', {
            title: title,
            video: videoUrl
        });
        console.log('[Metrika] Education view:', title);
    },

    // Клик по кнопке "Смотреть видео" в образовательных материалах
    educationVideoClick: function(title) {
        ym(106803279, 'reachGoal', 'education_video_click', {
            title: title
        });
        console.log('[Metrika] Education video click:', title);
    },

    // Донат
    donateClick: function() {
        ym(106803279, 'reachGoal', 'donate_click');
        console.log('[Metrika] Donate click');
    },

    // Переход в админ-панель
    adminPanelOpen: function() {
        ym(106803279, 'reachGoal', 'admin_panel_open');
        console.log('[Metrika] Admin panel opened');
    },

    // Отправка рассылки
    broadcastSent: function(recipientsCount) {
        ym(106803279, 'reachGoal', 'broadcast_sent', {
            recipients: recipientsCount
        });
        console.log('[Metrika] Broadcast sent to:', recipientsCount);
    },

    // Клик по категории
    categoryClick: function(categoryName) {
        ym(106803279, 'reachGoal', 'category_click', {
            category: categoryName
        });
        console.log('[Metrika] Category click:', categoryName);
    },

    // Переход на страницу образовательных материалов
    obrazovachPageView: function() {
        ym(106803279, 'reachGoal', 'obrazovach_page_view');
        console.log('[Metrika] Obrazovach page viewed');
    },

    // Переход на презентацию для партнеров
    presentationView: function() {
        ym(106803279, 'reachGoal', 'presentation_view');
        console.log('[Metrika] Presentation viewed');
    },

    // Клик по социальным сетям
    socialClick: function(network) {
        ym(106803279, 'reachGoal', 'social_click', {
            network: network
        });
        console.log('[Metrika] Social click:', network);
    },

    // Клик "Перезапустить бот"
    restartBotClick: function() {
        ym(106803279, 'reachGoal', 'restart_bot_click');
        console.log('[Metrika] Restart bot clicked');
    },

    // Принятие cookies
    cookiesAccepted: function() {
        ym(106803279, 'reachGoal', 'cookies_accepted');
        console.log('[Metrika] Cookies accepted');
    },

    // Клик "Стать партнером"
    becomePartnerClick: function() {
        ym(106803279, 'reachGoal', 'become_partner_click');
        console.log('[Metrika] Become partner clicked');
    },

    // Обратная связь с разработчиками
    feedbackClick: function() {
        ym(106803279, 'reachGoal', 'feedback_click');
        console.log('[Metrika] Feedback clicked');
    },

    // Просмотр политики конфиденциальности
    policyView: function() {
        ym(106803279, 'reachGoal', 'policy_view');
        console.log('[Metrika] Policy viewed');
    },

    // Просмотр оферты
    offerView: function() {
        ym(106803279, 'reachGoal', 'offer_view');
        console.log('[Metrika] Offer viewed');
    },

    // Custom event для любых других целей
    customEvent: function(eventName, params) {
        ym(106803279, 'reachGoal', eventName, params);
        console.log('[Metrika] Custom event:', eventName, params);
    }
};

console.log('[Metrika] Analytics initialized with ID: 106803279');
