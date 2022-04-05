/*==================== HIDE FLASHBOX ====================*/
const flashBox = document.getElementById('flashbox'),
      boxClose = document.getElementById('flashbox-close')

if(boxClose){
    boxClose.addEventListener('click', () =>{
        flashBox.classList.add('hidden')
    })
}

/*================= SHOW&HIDE HAMBURGER =================*/
const hamburger = document.querySelector(".nav__toggle");
const navMenu = document.querySelector(".nav__list");

hamburger.addEventListener("click", () => {
    hamburger.classList.toggle("active");
    navMenu.classList.toggle("active");
})

// document.querySelectorAll(".nav__link").forEach(n => n.addEventListener("click", () => {
//     hamburger.classList.remove("active");
//     navMenu.classList.remove("active");
// }))
