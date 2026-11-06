try {
  const storedTheme = localStorage.getItem('threattrack:dark-mode')
  const darkMode = storedTheme ? JSON.parse(storedTheme) : true
  document.documentElement.classList.toggle('dark', Boolean(darkMode))
} catch {
  document.documentElement.classList.add('dark')
}
