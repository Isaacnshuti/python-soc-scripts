document.addEventListener('DOMContentLoaded', () => {
  const body = document.body;
  body.classList.add('js-ready');

  const navbar = document.querySelector('.navbar');
  const menuToggle = document.querySelector('.menu-toggle');
  const navLinksWrap = document.querySelector('.nav-links');
  const navContainer = document.querySelector('.nav-container');
  const navLinks = Array.from(document.querySelectorAll('.nav-link'));

  const closeMenu = () => {
    if (!menuToggle || !navLinksWrap) return;
    navLinksWrap.classList.remove('active');
    menuToggle.setAttribute('aria-expanded', 'false');
  };

  if (menuToggle && navLinksWrap) {
    menuToggle.addEventListener('click', () => {
      const open = navLinksWrap.classList.toggle('active');
      menuToggle.setAttribute('aria-expanded', String(open));
    });

    document.addEventListener('click', (event) => {
      if (!navLinksWrap.classList.contains('active')) return;
      if (navContainer && navContainer.contains(event.target)) return;
      closeMenu();
    });

    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') closeMenu();
    });
  }

  // Smooth scrolling for in-page nav anchors.
  navLinks.forEach((link) => {
    link.addEventListener('click', (event) => {
      const href = link.getAttribute('href') || '';
      if (!href.startsWith('#')) return;
      const target = document.querySelector(href);
      if (!target) return;
      event.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      closeMenu();
    });
  });

  // Active nav state based on visible section.
  const sections = navLinks
    .map((link) => {
      const href = link.getAttribute('href') || '';
      if (!href.startsWith('#')) return null;
      const section = document.querySelector(href);
      return section ? { link, section } : null;
    })
    .filter(Boolean);

  const setActiveLink = (id) => {
    navLinks.forEach((link) => {
      const href = link.getAttribute('href') || '';
      link.classList.toggle('active', href === `#${id}`);
    });
  };

  if ('IntersectionObserver' in window && sections.length) {
    const sectionObserver = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          setActiveLink(entry.target.id);
        });
      },
      { threshold: 0.35 }
    );

    sections.forEach(({ section }) => sectionObserver.observe(section));
  }

  // Navbar state on scroll.
  const updateNavbarState = () => {
    if (!navbar) return;
    navbar.classList.toggle('scrolled', window.scrollY > 8);
  };

  updateNavbarState();
  window.addEventListener('scroll', updateNavbarState, { passive: true });

  // Reveal animation.
  const revealElements = Array.from(document.querySelectorAll('.fade-in-up'));
  revealElements.forEach((el, i) => {
    el.style.transitionDelay = `${(i % 4) * 80}ms`;
  });

  if ('IntersectionObserver' in window) {
    const revealObserver = new IntersectionObserver(
      (entries, observer) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        });
      },
      { threshold: 0.14, rootMargin: '0px 0px -10% 0px' }
    );

    revealElements.forEach((el) => revealObserver.observe(el));
  } else {
    revealElements.forEach((el) => el.classList.add('is-visible'));
  }
});
