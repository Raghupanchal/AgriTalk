document.addEventListener('DOMContentLoaded', () => {
    const registerLink = document.querySelector('.register-link');
    const formContainer = document.querySelector('.form-container');

    registerLink.addEventListener('click', (event) => {
        event.preventDefault();
        formContainer.innerHTML = `
            <form class="form-signup text-center" method="post" action="/register">
                <img class="mb-4 logo" src="./images/png agritalk logo.png" alt="Company Logo" width="82" height="65">
                <h1 class="h3 mb-3 fw-bold">Register</h1>
            
                <div class="form-floating mb-3">
                    <input type="text" class="form-control" id="floatingName" placeholder="Your Name" required>
                    <label for="floatingName">Name</label>
                </div>
                <div class="form-floating mb-3">
                    <input type="email" class="form-control" id="floatingEmail" placeholder="name@example.com" required>
                    <label for="floatingEmail">Email address</label>
                </div>
                <div class="form-floating mb-3">
                    <input type="password" class="form-control" id="floatingPassword" placeholder="Password" required>
                    <label for="floatingPassword">Password</label>
                </div>
                <button class="btn btn-primary w-100 py-2 button" type="submit">Register</button>
            </form>
        `;
    });
});
    