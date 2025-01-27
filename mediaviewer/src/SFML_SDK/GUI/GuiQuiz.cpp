#include "GuiQuiz.h"
#include <iostream>

namespace gui {

    const int SizeAnswer = 25;

    GuiQuiz::GuiQuiz(const std::string& name, float _w, float _h, float _h_text) : gui::Widget(name), w(_w), h(_h), h_text(_h_text)
    {
        m_rect.setOutlineThickness(1);
        m_rect.setOutlineColor(sf::Color::Green);
        m_rect.setFillColor(sf::Color::White);
        m_rect.setSize({ _w, _h });

        m_rect.setOutlineThickness(1);

        sf::Color cLine = sf::Color::Green; cLine.a = 128;
        sf::Color cFill = sf::Color::Black; cFill.a = 128;

        m_rect.setOutlineColor(cLine);
        m_rect.setFillColor(cFill);
    }

    bool GuiQuiz::is_loaded(const std::string& filename)
    {
        {
            for (size_t i = 0; i < v_quiz.size(); i++)
            {
                if (v_quiz[i].m_filename == filename)
                {
                    return true;
                }
            }
        }
        return false;
    }

    bool GuiQuiz::load_quiz(const std::string& filename)
    {
        if (is_loaded(filename) == true)
            return true;

        //reset();

        quiz_detail quiz;
        quiz.m_filename = filename;

        int r = quiz.m_quiz.read_xml(filename);

        if (r == XML_SUCCESS)
        {
            quiz.m_filename = filename;
            v_quiz.push_back(quiz);
            load(v_quiz.size() - 1);
            return true;
        }
        else
        {
            return false;
        }
    }

    void GuiQuiz::reset()
    {
        for (size_t i = 0; i < v_quiz.size(); i++)
        {
            v_quiz[i].m_filename.clear();
            v_quiz[i].b_subject.reset();
            v_quiz[i].b_question.reset();
            v_quiz[i].b_choices.clear();
            v_quiz[i].b_answers.clear();
            v_quiz[i].b_result.reset();
        }
        v_quiz.clear();
        quiz_idx = 0;
    }

    void  GuiQuiz::setSkin(int alpha, size_t idx)
    {
        if (v_quiz.size() == 0)
            return;

        if (idx >= v_quiz.size())
            return;

        sf::Color cLine = sf::Color::Green; cLine.a = alpha;
        sf::Color cFill = sf::Color::Black; cFill.a = alpha;

        m_rect.setOutlineColor(cLine);
        m_rect.setFillColor(cFill);

        {
            v_quiz[idx].b_subject->m_rect.setOutlineColor(cLine);
            v_quiz[idx].b_subject->m_rect.setFillColor(cFill);

            v_quiz[idx].b_question->m_rect.setOutlineColor(cLine);
            v_quiz[idx].b_question->m_rect.setFillColor(cFill);

            for (size_t i = 0; i <v_quiz[idx].m_quiz._choice.size(); i++)
            {
                v_quiz[idx].b_choices[i]->m_rect.setOutlineColor(cLine);
                v_quiz[idx].b_choices[i]->m_rect.setFillColor(cFill);

                v_quiz[idx].b_answers[i]->m_rect.setOutlineColor(cLine);
                v_quiz[idx].b_answers[i]->m_rect.setFillColor(cFill);
            }

            v_quiz[idx].b_result->m_rect.setOutlineColor(cLine);
            v_quiz[idx].b_result->m_rect.setFillColor(cFill);
        }
    }

    void GuiQuiz::set_quiz(size_t idx)
    {
        if (idx < v_quiz.size())
        {
            quiz_idx = idx;
            m_rect.setSize(sf::Vector2f(w, h_text * (3 + v_quiz[idx].m_quiz._choice.size())));
            for (size_t i = 0; i < v_quiz[idx].m_quiz._choice.size(); i++)
            {
                v_quiz[idx].b_answers[i]->setText("[ ]");
            }
        }
    }

    void GuiQuiz::load(size_t idx)
    {
        if (v_quiz.size() == 0)
            return;

        if (idx >= v_quiz.size())
            return;

        // ???
        m_rect.setSize(sf::Vector2f(w, h_text * (3 + v_quiz[idx].m_quiz._choice.size()) ) );

        v_quiz[idx].b_subject = makeSharedButton("subject");
        v_quiz[idx].b_subject->m_rect.setSize({ w, h_text });
        v_quiz[idx].b_subject->setText(v_quiz[idx].m_quiz._subject);
        v_quiz[idx].b_subject->setPosition(m_rect.getPosition() + sf::Vector2f(0.0f, 0 * h_text));

        v_quiz[idx].b_question = makeSharedButton("question");
        v_quiz[idx].b_question->m_rect.setSize({ w, h_text });
        v_quiz[idx].b_question->setText(v_quiz[idx].m_quiz._question);
        v_quiz[idx].b_question->setPosition(m_rect.getPosition() + sf::Vector2f(0.0f, 1 * h_text) );

        for (size_t i = 0; i <  v_quiz[idx].m_quiz._choice.size(); i++)
        {
            std::shared_ptr<Button> b = makeSharedButton("choice_" + std::to_string(i));
            b->m_rect.setSize({ w - SizeAnswer * 3, h_text });
            b->setText(std::to_string(i+1) + ". " + v_quiz[idx].m_quiz._choice[i]._text);
            b->setPosition(m_rect.getPosition() + sf::Vector2f(0.0f, (i+2) * h_text));

            v_quiz[idx].b_choices.push_back(b);

            std::shared_ptr<Button> ba = makeSharedButton("answer_" + std::to_string(i));
            ba->m_rect.setSize({ SizeAnswer * 3, h_text });
            ba->setText("[ ]");
            ba->setPosition(sf::Vector2f(w - SizeAnswer * 3, 0.0f) + sf::Vector2f(0.0f, (i + 2) * h_text));
            v_quiz[idx].b_answers.push_back(ba);
        }

        v_quiz[idx].b_result = makeSharedButton("result");
        v_quiz[idx].b_result->m_rect.setSize({ w, h_text });
        v_quiz[idx].b_result->setText(" ");
        v_quiz[idx].b_result->setPosition(m_rect.getPosition() + sf::Vector2f(0.0f, (v_quiz[idx].m_quiz._choice.size() + 2) * h_text));

        setSkin(128, idx);
    }

    void GuiQuiz::setTexture(const sf::Texture& tex)
    {
        m_rect.setTexture(&tex);
    }

    void GuiQuiz::handleEvent(sf::Event e, const sf::RenderWindow& win, StateBase& current_state)
    {
        auto pos = sf::Mouse::getPosition(win);
        sf::RenderWindow& window = (sf::RenderWindow&) (win);

        if (v_quiz.size() == 0)
            return;

        if (quiz_idx >= v_quiz.size())
            return;

        switch (e.type)
        {
        case sf::Event::MouseButtonPressed:
            switch (e.mouseButton.button)
            {
            case sf::Mouse::Left:
                //if (m_rect.getGlobalBounds().contains((float)pos.x, (float)pos.y))
                {
                    for (size_t i = 0; i < v_quiz[quiz_idx].b_choices.size(); i++)
                    {
                        if (v_quiz[quiz_idx].b_answers[i]->m_rect.getGlobalBounds().contains((float)pos.x, (float)pos.y))
                        {
                            answer_index_clicked = i;
                            std::string s = v_quiz[quiz_idx].b_answers[i]->m_text.getString();
                            if (s == "[ ]") s = "[X]";
                            else s = "[ ]";

                            v_quiz[quiz_idx].b_answers[i]->setText(s);

                            if (isAnswerOK() == true)
                            {
                                v_quiz[quiz_idx].b_result->setText(" Bravo! ");
                                std::invoke(m_state_func, &current_state, name);
                            }
                            else
                            {
                                v_quiz[quiz_idx].b_result->setText(" ... ");
                            }

                            //std::invoke(m_state_func, &current_state, name);
                            break;
                        }
                    }
                }

            default:
                break;
            }

        default:
            break;
        }
    }

    bool GuiQuiz::isAnswerIndexSelected(size_t index) const
    {
        if ((index < 0) || (index >= v_quiz[quiz_idx].b_answers.size()))
            return false;

        std::string s = v_quiz[quiz_idx].b_answers[index]->m_text.getString();
        if (s == "[X]") return true;
        return false;
    }

    bool GuiQuiz::isAnswerOK() const
    {
        if (v_quiz[quiz_idx].b_answers.size() == 0) return true;
        for (size_t i = 0; i <  v_quiz[quiz_idx].m_quiz._choice.size(); i++)
        {
            bool selected = isAnswerIndexSelected(i);
            if ((v_quiz[quiz_idx].m_quiz._choice[i]._is_true == true) && (selected == false)) return false;
            if ((v_quiz[quiz_idx].m_quiz._choice[i]._is_true == false) && (selected == true)) return false;
        }
        return true;
    }


    void GuiQuiz::render(sf::RenderTarget& renderer)
    {
        if ((v_quiz.size() > 0) && (quiz_idx < v_quiz.size()))
        {
            if (isAnswerOK() == true)
            {
                v_quiz[quiz_idx].b_result->setText(" Bravo! ");
            }
            else
            {
                v_quiz[quiz_idx].b_result->setText(" ... ");
            }

            renderer.draw(m_rect);
            v_quiz[quiz_idx].b_subject->render(renderer);
            v_quiz[quiz_idx].b_question->render(renderer);
            for (size_t i = 0; i <  v_quiz[quiz_idx].b_choices.size(); i++)
            {
                v_quiz[quiz_idx].b_choices[i]->render(renderer);
                v_quiz[quiz_idx].b_answers[i]->render(renderer);
            }
            v_quiz[quiz_idx].b_result->render(renderer);
        }
    }

    void GuiQuiz::setPosition(const sf::Vector2f& pos)
    {
        m_position = pos;
        m_rect.setPosition(m_position);

        if ( (v_quiz.size() > 0) && (quiz_idx < v_quiz.size()) )
        {
            v_quiz[quiz_idx].b_subject->setPosition(m_rect.getPosition() + sf::Vector2f(0.0f, 0 * h_text));
            v_quiz[quiz_idx].b_question->setPosition(m_rect.getPosition() + sf::Vector2f(0.0f, 1 * h_text));

            for (size_t i = 0; i <  v_quiz[quiz_idx].m_quiz._choice.size(); i++)
            {
                v_quiz[quiz_idx].b_choices[i]->setPosition(m_rect.getPosition() + sf::Vector2f(0.0f, (i + 2) * h_text));
                v_quiz[quiz_idx].b_answers[i]->setPosition(sf::Vector2f(m_rect.getPosition().x + m_rect.getSize().x - SizeAnswer * 3, 0.0f) + sf::Vector2f(0.0f, (i + 2) * h_text));
            }
            v_quiz[quiz_idx].b_result->setPosition(m_rect.getPosition() + sf::Vector2f(0.0f, (v_quiz[quiz_idx].m_quiz._choice.size() + 2) * h_text));
        }
    }

    sf::Vector2f GuiQuiz::getSize() const
    {
        return m_rect.getSize();
    }
}
