//
#include "States/StateBase.h"
#include "Game.h"
#include <iostream>
#include <string>
#include "SFML_SDK/ResourceManager/ResourceHolder.h"

Game::Game(int w, int h, std::string title, const std::string& apath_to_res)
:   m_window({(unsigned int)w, (unsigned int)h}, title)
{
    ResourceHolder::init(apath_to_res);

    m_window.setPosition({m_window.getPosition().x, 0});
    m_window.setFramerateLimit(60);
}

// Runs the main loop
void Game::run()
{
    constexpr unsigned TPS = 30; // ticks per seconds
    const sf::Time     timePerUpdate = sf::seconds(1.0f / float(TPS));
    unsigned ticks = 0;

    sf::Clock timer;
    auto lastTime = sf::Time::Zero;
    auto lag      = sf::Time::Zero;

    // Main loop of the game
    while (m_window.isOpen() && !m_states.empty())
    {
        auto& state = getCurrentState();

        // Get times
        auto time = timer.getElapsedTime();
        auto elapsed = time - lastTime;
        lastTime = time;
        lag += elapsed;

        // Real time update
        state.handleInput();
        state.update(elapsed);
        counter.update();

        // Fixed time update
        while (lag >= timePerUpdate)
        {
            ticks++;
            lag -= timePerUpdate;
            state.fixedUpdate(elapsed);
        }

        // Render
        m_window.clear();
        state.render(m_window);
        counter.draw(m_window);
        m_window.display();

        // Handle window events
        handleEvent();
        tryPop();
    }
}

// Tries to pop the current game state
void Game::tryPop()
{
    if (m_shouldPop)
    {
        m_shouldPop = false;
        if (m_shouldExit)
        {
            m_states.clear();
            return;
        }
        else if (m_shouldChageState)
        {
            m_shouldChageState = false;
            m_states.pop_back();
            pushState(std::move(m_change));
            return;
        }

        m_states.pop_back();
    }
}

// Handles window events, called every frame
void Game::handleEvent()
{
    sf::Event e;
    sf::View view = m_window.getDefaultView();

    while (m_window.pollEvent(e))
    {
        //---------------------------------
        // widgets event
        //---------------------------------
        getCurrentState().handleEvent(e);

        //---------------------------------
        // window event
        //---------------------------------
        switch (e.type)
        {
            case sf::Event::Closed:
                m_window.close();
                break;

            case sf::Event::Resized:
                m_window.setView(sf::View(sf::FloatRect(0, 0, (float)e.size.width, (float)e.size.height)));
                break;

            default:
                break;
        }
    }
}

// Returns a reference to the current game state
StateBase& Game::getCurrentState()
{
    return *m_states.back();
}

void Game::pushState(std::unique_ptr<StateBase> state)
{
    m_states.push_back(std::move(state));
}

// Flags a boolean for the game to pop state
void Game::popState()
{
    m_shouldPop = true;
}

void Game::exitGame()
{
    m_shouldPop = true;
    m_shouldExit = true;
}

sf::RenderWindow& Game::getWindow()
{
    return m_window;
}
